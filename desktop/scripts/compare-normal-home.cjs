'use strict';
// One approved comparison. This observer never changes or rebuilds the candidate.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { spawn, spawnSync, execFileSync } = require('node:child_process');
const { EXPECTED, verifyCandidate } = require('./diagnose-cookie-hang.cjs');
const FIXED_HASHES = Object.freeze({
  executable_sha256: 'aefb3e30603c15f83945f240ed377148887eaebd65d783d31f59f335423ba4ca',
  asar_sha256: '8ca8c80471c94c6c7b69d3a2646a19e9529efc95984163d9ab5f25b036df6bd6',
});
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const hash = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
function normalEnvironment(home, source = process.env) {
  assert.ok(typeof home === 'string' && path.isAbsolute(home), 'Existing runner HOME required');
  const env = { HOME: home, PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LC_ALL: 'en_US.UTF-8', TZ: 'UTC' };
  for (const key of ['TMPDIR', 'USER', 'LOGNAME']) if (source[key]) env[key] = source[key];
  return env;
}
function absenceResult(result) {
  if (result.error || result.signal || ![0, 1].includes(result.status)) throw new Error('SecurityAgent query unavailable');
  return result.status === 1;
}
function assertWindowObservation(value, requireVisible = false, baseline = null) {
  assert.equal(value?.query_ok, true, 'Window query unavailable');
  assert.ok(Array.isArray(value.chrome_signatures) && value.chrome_signatures.every(s => typeof s === 'string' && /^\d+:-?\d+$/.test(s)), 'Chrome window metadata unavailable');
  if (baseline) assert.ok(value.chrome_signatures.every(s => baseline.includes(s)), 'New system chrome window observed; stop without interaction');
  assert.equal(value.security_ui_present, false, 'Security or authorization UI observed; stop without interaction');
  assert.equal(value.permission_title_observed, false, 'Permission-like window observed; stop without interaction');
  assert.equal(value.unexpected_window, false, 'Unexpected normal-layer window observed; stop without interaction');
  if (requireVisible) assert.equal(value.app_windows, 1, 'Expected visible app window is not observable');
  assert.ok(Number.isInteger(value.app_windows) && value.app_windows >= 0 && value.app_windows <= 1, 'Unexpected app modal/window observed; stop without interaction');
}
function assertCleanPhase(result, report) {
  assert.equal(result.code, 0, 'App must exit successfully');
  assert.equal(result.signal, null, 'Forced exit is not normal shutdown');
  assert.equal(result.error, undefined, 'App spawn failed');
  assert.equal(report?.status, 'passed', 'Native phase must pass before reopen');
  assert.ok(report.checks.includes('normal_app_quit_closed_views_released_leases_and_stopped_sidecar'), 'Normal shutdown check missing');
  assert.equal(result.sidecar_process_gone, true, 'Owned sidecar must be gone before reopen');
}
function alive(pid) {
  assert.ok(Number.isInteger(pid) && pid > 1, 'Invalid owned process PID');
  try { process.kill(pid, 0); return true; } catch (error) { if (error.code === 'ESRCH') return false; throw error; }
}
async function main() {
  const desktop = path.resolve(__dirname, '..');
  const input = path.join(desktop, 'diagnostic-input');
  const output = path.join(desktop, 'out/normal-home-comparison');
  fs.mkdirSync(output, { recursive: true });
  const report = { kind: 'immutable-candidate-normal-HOME-comparison', status: 'failed', ...EXPECTED, ...FIXED_HASHES,
    observer_source_commit: process.env.GITHUB_SHA || null, native_acceptance: false, install_ready: false,
    packaged_synthetic_storage_smoke: false, launches: 0,
    exclusions: ['Real accounts and sign-in', 'Anti-detect qualification', 'Proxy, network, DNS and TLS leaks', 'Service workers and cache', 'Signing, notarization, Gatekeeper and installation'],
    keychain_scope: 'Existing disposable runner Keychain only; app may create its own cookie-encryption item. No item query or setting changes.',
    observation_limitations: ['Window metadata must remain observable or the test stops. Short-lived prompts between 200ms observations may be missed.', 'No prompt clicked or permission granted.'] };
  let root, archive, executable, asar;
  const evidenceNames = [];
  function save(name, content) {
    const data = Buffer.isBuffer(content) ? content : Buffer.from(content);
    const total = fs.readdirSync(output).filter(n => n !== name).reduce((sum,n) => sum + fs.statSync(path.join(output,n)).size, 0);
    if (name !== 'comparison.json' && total + data.length + 65536 > 1024 * 1024) {
      (report.omitted_evidence ||= []).push(name); return false;
    }
    assert.ok(total + data.length <= 1024 * 1024, 'Evidence exceeds one MiB');
    fs.writeFileSync(path.join(output,name), data); return true;
  }
  const summary = () => save('comparison.json', JSON.stringify(report,null,2)+'\n');
  const redact = text => [root, root && fs.realpathSync(root), process.env.HOME].filter(Boolean).reduce((s,p) => s.split(p).join('[ISOLATED_PATH]'), text).replace(/[\x00-\x08\x0b-\x1f\x7f]/g,'');
  let guard, chromeBaseline = null;
  function readPhase(phase) {
    const file = path.join(root,'evidence',phase+'.json');
    if (!fs.existsSync(file)) return null;
    assert.ok(fs.statSync(file).size <= 65536, 'Native phase evidence too large');
    try { return JSON.parse(fs.readFileSync(file,'utf8')); } catch (error) { if (error instanceof SyntaxError) return null; throw error; }
  }
  async function phase(name) {
    guard(); // Absent and observable before each launch; no retry if not.
    const env = normalEnvironment(process.env.HOME);
    const child = spawn(executable, [`--tbm-native-smoke-root=${root}`, `--tbm-native-smoke-phase=${name}`], {cwd:root,env,shell:false,stdio:['ignore','pipe','pipe']});
    let exited = false, result = {}, last;
    const logs = []; let bytes = 0;
    child.once('error', e => { result.error=e.code || 'spawn_error'; exited=true; });
    child.once('exit',(code,signal) => { result.code=code; result.signal=signal; exited=true; });
    for (const stream of [child.stdout,child.stderr]) stream.on('data', chunk => { if(bytes<32768){logs.push(chunk.subarray(0,32768-bytes));bytes+=chunk.length;} });
    try {
      report.launches++; summary();
      const deadline=Date.now()+120000;
      while (!exited) {
        last = readPhase(name);
        guard(Boolean(last?.checks?.includes('real_browser_window_and_settled_profile_manager_rendered') && last.status === 'running' && alive(child.pid)));
        if(last?.status === 'failed') throw new Error(`Native ${name} failed: ${last.failed_operation || last.failure || 'unknown operation'}`);
        if(Date.now() >= deadline) throw new Error(`Native ${name} timed out: ${last?.active_operation || 'startup/shutdown'}`);
        await sleep(200);
      }
      guard();
      last=readPhase(name);
      if(Number.isInteger(last?.sidecar_pid)) {
        const deadline=Date.now()+10000;
        while(alive(last.sidecar_pid) && Date.now()<deadline){guard();await sleep(100);}
        result.sidecar_process_gone=!alive(last.sidecar_pid);
      }
      assertCleanPhase(result,last);
      report[name]={...result,checks:last.checks}; summary();
    } finally {
      if(!exited) {
        result.cleanup='SIGTERM requested for owned app; this is not normal-shutdown acceptance'; child.kill('SIGTERM');
        const deadline=Date.now()+5000; while(!exited && Date.now()<deadline) await sleep(100);
        if(!exited){child.kill('SIGKILL');result.cleanup='Owned app forced termination; no reopen';await sleep(300);}
      }
      last=readPhase(name);
      report[name] ||= {...result,last_native_operation:last?.failed_operation || last?.active_operation || null};
      save(name+'-process.log',redact(Buffer.concat(logs).toString('utf8')).slice(0,32768));
      for(const suffix of ['.json','-chrome.png','-profiles-chrome.png','-profile-A.png','-profile-B.png']) {
        const file=path.join(root,'evidence',name+suffix);
        if(fs.existsSync(file) && fs.statSync(file).size <= (suffix==='.json'?65536:131072)) {
          const data=fs.readFileSync(file); if(evidenceNames.length < 10){save(name+suffix,suffix==='.json'?redact(data.toString('utf8')):data);evidenceNames.push(name+suffix);}
        }
      }
      summary();
    }
  }
  try {
    assert.equal(process.platform,'darwin'); assert.equal(process.arch,'arm64');
    assert.equal(process.env.GITHUB_ACTIONS,'true'); assert.equal(process.env.RUNNER_ENVIRONMENT,'github-hosted');
    const home=process.env.HOME;
    normalEnvironment(home); assert.equal(fs.statSync(home).isDirectory(),true);
    const candidate=JSON.parse(fs.readFileSync(path.join(input,'candidate.json'),'utf8'));
    assert.equal(path.basename(candidate.archive),candidate.archive);
    archive=path.join(input,candidate.archive); verifyCandidate(candidate,hash(archive));
    root=fs.mkdtempSync(path.join(os.tmpdir(),'tbm-native-smoke-'));fs.chmodSync(root,0o700);
    fs.writeFileSync(path.join(root,'fixture-marker'),'TeamBrowser blank native smoke v1\n',{mode:0o600});
    for(const name of ['home','evidence','extracted']) fs.mkdirSync(path.join(root,name),{mode:0o700});
    const observer=path.join(root,'observe-permission-windows');
    execFileSync('/usr/bin/clang',[path.join(__dirname,'observe-permission-windows.c'),'-framework','CoreGraphics','-framework','CoreFoundation','-o',observer],{timeout:30000,stdio:'pipe',maxBuffer:65536});
    guard=(requireVisible=false)=>{
      const securityQuery = spawnSync('/usr/bin/pgrep',['-x','SecurityAgent'],{timeout:3000,stdio:'ignore'});
      report.last_security_agent_observation = securityQuery.status === 0 ? 'present' : securityQuery.status === 1 && !securityQuery.error && !securityQuery.signal ? 'absent' : 'unavailable';
      assert.equal(absenceResult(securityQuery),true,'SecurityAgent observed; stop without interaction');
      const raw=execFileSync(observer,[],{timeout:3000,encoding:'utf8',maxBuffer:4096});
      const observation = JSON.parse(raw);
      report.last_window_observation = { query_ok: observation.query_ok, security_ui_present: observation.security_ui_present, permission_title_observed: observation.permission_title_observed, unexpected_window: observation.unexpected_window, app_windows: observation.app_windows };
      assertWindowObservation(observation,requireVisible,chromeBaseline);
      chromeBaseline ||= observation.chrome_signatures;
    };
    guard();report.initial_permission_observation='absent';
    execFileSync('/usr/bin/ditto',['-x','-k',archive,path.join(root,'extracted')],{timeout:60000,stdio:'pipe'});
    const bundle=path.join(root,'extracted/TeamBrowser.app');
    executable=path.join(bundle,'Contents/MacOS/TeamBrowser');asar=path.join(bundle,'Contents/Resources/app.asar');
    assert.equal(hash(executable),FIXED_HASHES.executable_sha256);assert.equal(hash(asar),FIXED_HASHES.asar_sha256);
    execFileSync('/usr/bin/codesign',['--verify','--deep','--strict',bundle],{timeout:30000,stdio:'pipe',maxBuffer:65536});report.existing_signature_valid=true;
    await phase('seed');
    await phase('reopen');
    report.packaged_synthetic_storage_smoke=true;report.status='passed';
  } catch(error) {report.failure=redact(String(error.message)).slice(0,4096);process.exitCode=1;}
  finally {
    if(archive && executable && asar && fs.existsSync(executable) && fs.existsSync(asar)) {
      report.candidate_bytes_unchanged=hash(archive)===EXPECTED.archive_sha256 && hash(executable)===FIXED_HASHES.executable_sha256 && hash(asar)===FIXED_HASHES.asar_sha256;
      if(!report.candidate_bytes_unchanged){report.status='failed';report.packaged_synthetic_storage_smoke=false;process.exitCode=1;}
    }
    summary();console.log(JSON.stringify(report,null,2));
  }
}
if(require.main === module) void main();
module.exports={FIXED_HASHES,normalEnvironment,absenceResult,assertWindowObservation,assertCleanPhase};
