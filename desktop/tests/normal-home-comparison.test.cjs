'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {FIXED_HASHES,normalEnvironment,absenceResult,assertWindowObservation,assertCleanPhase}=require('../scripts/compare-normal-home.cjs');
const root=path.resolve(__dirname,'../..');
const script=fs.readFileSync(path.join(root,'desktop/scripts/compare-normal-home.cjs'),'utf8');
const observer=fs.readFileSync(path.join(root,'desktop/scripts/observe-permission-windows.c'),'utf8');
const workflow=fs.readFileSync(path.join(root,'.github/workflows/desktop-normal-home-comparison.yml'),'utf8');
test('normal process HOME preserves only bounded launch environment',()=>{
 const env=normalEnvironment('/Users/runner',{HOME:'/wrong',GITHUB_TOKEN:'never',ELECTRON_DISABLE_SANDBOX:'1',HTTP_PROXY:'never',NODE_OPTIONS:'never',TMPDIR:'/tmp',USER:'runner',LOGNAME:'runner'});
 assert.deepEqual(env,{HOME:'/Users/runner',PATH:'/usr/bin:/bin:/usr/sbin:/sbin',LC_ALL:'en_US.UTF-8',TZ:'UTC',TMPDIR:'/tmp',USER:'runner',LOGNAME:'runner'});
});
for(const value of [undefined,'','relative',null]) test(`HOME rejects ${String(value)}`,()=>assert.throws(()=>normalEnvironment(value)));
test('only successful explicit absence permits starting',()=>{assert.equal(absenceResult({status:1}),true);assert.equal(absenceResult({status:0}),false);});
for(const result of [{status:null},{status:2},{status:1,error:new Error('blocked')},{status:1,signal:'SIGTERM'}]) test(`unavailable process query fails closed ${JSON.stringify(result)}`,()=>assert.throws(()=>absenceResult(result)));
const clean={query_ok:true,security_ui_present:false,permission_title_observed:false,unexpected_window:false,app_windows:1,chrome_signatures:['1:24'],menu_signatures:[]};
test('normal single app window observed',()=>assertWindowObservation(clean));
for(const change of [{query_ok:false},{unexpected_window:true},{security_ui_present:true},{permission_title_observed:true},{app_windows:2},{app_windows:-1},{app_windows:null},{app_windows:1.5}]) test(`window guard rejects ${JSON.stringify(change)}`,()=>assert.throws(()=>assertWindowObservation({...clean,...change})));
const result={code:0,signal:null,sidecar_process_gone:true};
const report={status:'passed',checks:['normal_app_quit_closed_views_released_leases_and_stopped_sidecar']};
test('normal successful seed is allowed',()=>assertCleanPhase(result,report));
for(const change of [{code:1},{signal:'SIGTERM'},{sidecar_process_gone:false},{error:'ENOENT'}]) test(`reopen rejects unsuccessful prior process ${JSON.stringify(change)}`,()=>assert.throws(()=>assertCleanPhase({...result,...change},report)));
for(const change of [{status:'failed'},{status:'awaiting_normal_shutdown'},{checks:[]}]) test(`reopen rejects incomplete prior smoke ${JSON.stringify(change)}`,()=>assert.throws(()=>assertCleanPhase(result,{...report,...change})));
test('archive, executable and ASAR retain fixed known identities',()=>{
 assert.equal(FIXED_HASHES.executable_sha256,'aefb3e30603c15f83945f240ed377148887eaebd65d783d31f59f335423ba4ca');
 assert.equal(FIXED_HASHES.asar_sha256,'8ca8c80471c94c6c7b69d3a2646a19e9529efc95984163d9ab5f25b036df6bd6');
 assert.match(script,/verifyCandidate\(candidate,hash\(archive\)\)/);assert.match(script,/candidate_bytes_unchanged/);
});
test('seed must finish before one reopen; no retry loop',()=>{
 assert.match(script,/await phase\('seed'\);\s+await phase\('reopen'\);/);assert.match(script,/assertCleanPhase\(result,last\)/);
 assert.equal((script.match(/await phase\(/g)||[]).length,2);
});
test('strict deadlines and prompt checks exist before and during launch',()=>{
 assert.match(script,/120000/);assert.match(script,/timeout:3000/);assert.match(script,/guard\(\); \/\/ Absent/);assert.match(script,/while \(!exited\) \{\s+last = readPhase\(name\);\s+guard\(/);
 assert.match(script,/last\?\.status === 'failed'/);assert.match(script,/SIGKILL/);
});
test('observer contains only read-only window API and no prompt interaction',()=>{
 assert.match(observer,/CGWindowListCopyWindowInfo/);assert.doesNotMatch(observer,/AXUIElement|CGEvent|SecKeychain|SecItem|osascript|CGRequestScreenCaptureAccess/);
 assert.match(observer,/SecurityAgent/);assert.match(observer,/app_windows/);
});
test('no security weakening, rebuild, keychain mutations or actual credentials',()=>{
 assert.doesNotMatch(script,/unlock-keychain|create-keychain|delete-keychain|set-keychain|list-keychains|default-keychain|partition-list|mock-keychain|disable-features|no-sandbox|use-mock-keychain|password-store|xattr|codesign.*--force|sudo/);
 assert.match(script,/\['--verify','--deep','--strict',bundle\]/);
});
test('workflow is manual standard runner with read-only token and immutable input',()=>{
 assert.match(workflow,/workflow_dispatch:/);assert.doesNotMatch(workflow,/\bpush:|schedule:|self-hosted|macos-.*large|package:mac|npm ci|PyInstaller/);
 assert.match(workflow,/runs-on: macos-15/);assert.match(workflow,/contents: read/);assert.match(workflow,/actions: read/);assert.match(workflow,/persist-credentials: false/);
 assert.match(workflow,/artifact-ids: '11310884356'/);assert.match(workflow,/run-id: '37224078859'/);
});
test('only bounded evidence is uploaded for one day, no candidate or HOME upload',()=>{
 assert.match(workflow,/path: desktop\/out\/normal-home-comparison\//);assert.match(workflow,/retention-days: 1/);
 const upload = workflow.split('uses: actions/upload-artifact@v4')[1];
 assert.doesNotMatch(upload,/out\/\*\.zip|path:.*diagnostic-input|path:.*user-data|path:.*session-data/);
 assert.match(script,/1024 \* 1024/);assert.match(script,/native_acceptance: false, install_ready: false/);
});

test('after render an unobservable app is a stop',()=>assert.throws(()=>assertWindowObservation({...clean,app_windows:0},true)));

test('new or unavailable system chrome is a stop',()=>{assert.throws(()=>assertWindowObservation(clean,false,[]));assert.throws(()=>assertWindowObservation({...clean,chrome_signatures:null}));assertWindowObservation(clean,false,['1:24']);});

const menuKey='100:200:25:34:24:abcdef1234567890';
test('menu baseline permits only the exact frozen surfaces',()=>{
 const menus={...clean,menu_signatures:[menuKey]};
 assertWindowObservation(menus,false,['1:24'],[menuKey]);
 for(const keys of [[],[menuKey.replace('100:','101:')],[menuKey.replace(':200:',':201:')],[menuKey.replace(':34:',':147:')],[menuKey.replace('abcdef','fedcba')]]) assert.throws(()=>assertWindowObservation({...menus,menu_signatures:keys},false,['1:24'],[menuKey]));
});
test('missing, duplicated or excessive menu metadata stops',()=>{
 for(const keys of [null,[menuKey,menuKey],[menuKey,'101:200:25:34:24:abcdef1234567890','102:200:25:34:24:abcdef1234567890','103:200:25:34:24:abcdef1234567890']]) assert.throws(()=>assertWindowObservation({...clean,menu_signatures:keys}));
});
