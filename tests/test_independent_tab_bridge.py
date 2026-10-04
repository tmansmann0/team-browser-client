"""Independent loopback and synthetic DOM contracts; no rendered/native browser."""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from team_browser.client import ProcessStatus, create_local_app


ROOT = Path(__file__).resolve().parents[1]
NODE_HARNESS = r"""
const assert = require('node:assert/strict'), fs = require('node:fs'), vm = require('node:vm');
const tabSource = fs.readFileSync('src/team_browser/static/tab_workspace.js', 'utf8');
const workspaceSource = fs.readFileSync('src/team_browser/static/workspace.js', 'utf8');
const id = 'tab_' + '9'.repeat(32), profile = {id:'local_review', revision:8, generation:4};
const snapshot = (extra={}) => ({profile_id:profile.id, generation:4, status:'ready', truncated:false,
  tabs:[{id, title:'<img src=x onerror=alert(1)>', origin:'https://review.test', active:true}],
  active_tab_id:id, active_evidence:'dom_visibility_hint', focus:{status:'idle'}, ...extra});
const settle = () => new Promise(r => setImmediate(r));
const deferred = () => {let resolve,reject; const promise=new Promise((r,j)=>{resolve=r;reject=j}); return {promise,resolve,reject}};
function fixture() {
  const doc={activeElement:null}, timers=new Map(), calls=[], notices=[]; let serial=0;
  class Element {
    constructor(tag) {this.tagName=tag;this.children=[];this.dataset={};this.attrs={};this.listeners={};this.textContent='';this.disabled=false;}
    set innerHTML(_) {throw new Error('Untrusted metadata reached innerHTML');}
    append(...children) {this.children.push(...children);}
    replaceChildren(...children) {this.children=children;}
    setAttribute(name,value) {this.attrs[name]=value;}
    addEventListener(name,fn) {this.listeners[name]=fn;}
    focus() {doc.activeElement=this;}
  }
  doc.createElement=tag=>new Element(tag); const root=new Element('section'), window={};
  vm.runInNewContext(tabSource,{window,document:doc,URL,AbortController,setTimeout,clearTimeout});
  let handler=async()=>snapshot();
  const ui=window.TeamNativeTabs.mount({document:doc,
    request:async(path,options)=>{calls.push({path,options});return handler(path,options)},
    notify:notice=>notices.push(notice), schedule:(fn,ms)=>{const id=++serial;timers.set(id,{fn,ms});return id},
    cancel:id=>timers.delete(id)});
  const all=(el=root)=>[el,...el.children.flatMap(child=>all(child))];
  const fire=ms=>{const item=[...timers].find(([id,t])=>t.ms===ms);assert(item,'Missing timer '+ms);timers.delete(item[0]);item[1].fn()};
  return {ui,root,calls,notices,timers,all,fire,setHandler:fn=>handler=fn,normalize:window.TeamNativeTabs.normalize};
}
(async()=>{
"""


@unittest.skipUnless(shutil.which("node"), "Node required for synthetic DOM contracts")
class IndependentTabDOMTests(unittest.TestCase):
    def run_js(self, scenario):
        result = subprocess.run(
            [
                "node",
                "-e",
                NODE_HARNESS + scenario + "\n})().catch(e=>{console.error(e);process.exitCode=1});",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_ready_cannot_hide_explicit_incomplete_snapshot(self):
        self.run_js(r"""
const t=fixture(); t.setHandler(async()=>snapshot({truncated:true}));
t.ui.activate(t.root,profile); await settle();
assert.equal(t.ui.state.snapshot,null);
assert.equal(t.all().filter(x=>x.dataset.nativeTab).length,0);
t.ui.deactivate();
""")

    def test_tab_ids_require_exact_string_without_line_terminator(self):
        self.run_js(r"""
const t=fixture();
for(const invalid of [id+'\n',id+'\r',id+'\u2028',[id],{id},null,9]) {
  assert.throws(()=>t.normalize(snapshot({tabs:[{...snapshot().tabs[0],id:invalid}]}),profile), 'Accepted noncanonical opaque ID');
}
""")

    def test_fixed_transport_rejects_browser_normalized_path_escapes(self):
        self.run_js(r"""
const window={};vm.runInNewContext(workspaceSource,{window});const seen=[];
const request=window.TeamWorkspace.createClient({getConfig:()=>({mode:'local',api_base:'/local/v1',csrf_token:'synthetic'}),
 fetcher:async(url,options)=>{seen.push({url,options});return{ok:true,status:200,json:async()=>({})}}});
for(const path of ['/profiles/..\\..\\..\\outside/actions','/profiles/%2e%2e/actions','/profiles/a%2fb/tab-focus',
 '/profiles/a#fragment/tab-focus','/profiles/..\\tabs/tab-focus','/tabs\u2028','/tabs\u2029']) {
 await assert.rejects(()=>request(path,{method:'POST',body:{synthetic:true}}));
}
assert.equal(seen.length,0);
await request('/profiles/local_review/tab-focus',{method:'POST',body:{tab_id:id,generation:4,expected_revision:8}});
assert.equal(seen.length,1);assert.equal(seen[0].url,'/local/v1/profiles/local_review/tab-focus');
assert.equal(seen[0].options.credentials,'omit');assert.equal(seen[0].options.cache,'no-store');
assert.equal(seen[0].options.headers['X-Local-CSRF'],'synthetic');
""")

    def test_expiry_removes_controls_and_blocks_old_listener_during_hung_poll(self):
        self.run_js(r"""
const t=fixture();t.ui.activate(t.root,profile);await settle();
const old=t.all().find(x=>x.dataset.nativeTab===id);assert(old);
const held=deferred();t.setHandler(()=>held.promise);const pending=t.ui.poll();
t.fire(5000);assert.equal(t.ui.state.snapshot,null);assert.equal(t.all().filter(x=>x.dataset.nativeTab).length,0);
await old.listeners.click();assert(!t.calls.some(x=>x.options?.method==='POST'));
held.reject(new Error('synthetic timeout'));await pending;t.ui.deactivate();
""")

    def test_new_poll_wins_when_aborted_old_response_still_resolves(self):
        self.run_js(r"""
const t=fixture(),old=deferred();t.setHandler(()=>old.promise);t.ui.activate(t.root,profile);
t.setHandler(async()=>snapshot({tabs:[{...snapshot().tabs[0],title:'Newest safe title'}]}));await t.ui.poll();
old.resolve(snapshot({tabs:[{...snapshot().tabs[0],title:'Retired title'}]}));await settle();
assert.equal(t.ui.state.snapshot.tabs[0].title,'Newest safe title');
assert(!t.all().some(x=>x.textContent==='Retired title'));t.ui.deactivate();
""")

    def test_same_profile_restart_generation_discards_retired_response(self):
        self.run_js(r"""
const t=fixture(),held=deferred();t.setHandler(()=>held.promise);t.ui.activate(t.root,profile);
t.setHandler(async()=>snapshot({generation:5,tabs:[{...snapshot().tabs[0],id:'tab_'+'8'.repeat(32)}]}));
t.ui.activate(t.root,{...profile,generation:5,revision:9});await settle();held.resolve(snapshot());await settle();
assert.equal(t.ui.state.snapshot.generation,5);assert(!t.all().some(x=>x.dataset.nativeTab===id));t.ui.deactivate();
""")

    def test_untrusted_titles_use_text_and_pending_ack_is_not_success(self):
        self.run_js(r"""
const t=fixture();t.ui.activate(t.root,profile);await settle();
assert(t.all().some(x=>x.textContent===snapshot().tabs[0].title));assert(!t.all().some(x=>x.tagName==='img'));
t.setHandler(async path=>path==='/tabs'?snapshot({focus:{status:'pending'}}):
 {outcome:'queued',profile_id:profile.id,generation:4,tab_id:id});
await t.ui.focus(id);assert(t.all().some(x=>x.textContent==='Focus requested; waiting for the browser.'));
assert(!t.all().some(x=>x.textContent==='The browser acknowledged the focus request.'));
const post=t.calls.find(x=>x.options?.method==='POST');
assert.deepEqual(JSON.parse(JSON.stringify(post.options.body)),{tab_id:id,generation:4,expected_revision:8});
t.ui.deactivate();
""")

    def test_retirement_aborts_pending_focus_and_late_reply_cannot_recreate_view(self):
        self.run_js(r"""
const t=fixture();t.ui.activate(t.root,profile);await settle();const held=deferred();
t.setHandler(()=>held.promise);const pending=t.ui.focus(id);const signal=t.calls.at(-1).options.signal;
t.ui.deactivate();assert(signal.aborted);
// A request deadline can remain until the aborted request settles; no polling may remain.
assert([...t.timers.values()].every(timer=>timer.ms===8000));
held.resolve({outcome:'queued',profile_id:profile.id,generation:4,tab_id:id});await pending;
assert.equal(t.root.children.length,0);assert.equal(t.ui.state.snapshot,null);assert.equal(t.timers.size,0);
assert.equal(t.calls.length,2);
""")

    def test_workspace_modes_and_nonprofile_views_retire_real_tab_component(self):
        self.run_js(r"""
const entries=new Map(),doc={activeElement:null};
function element(key) {
 if(entries.has(key))return entries.get(key);
 const e={children:[],dataset:{},attrs:{},listeners:{},textContent:'',innerHTML:'',open:false,value:'',
  addEventListener(name,fn){this.listeners[name]=fn},setAttribute(k,v){this.attrs[k]=v},removeAttribute(k){delete this.attrs[k]},
  querySelectorAll(){return[]},replaceChildren(...children){this.children=children},append(...children){this.children.push(...children)},
  appendChild(child){this.children.push(child)},focus(){doc.activeElement=this},close(){this.open=false},showModal(){this.open=true}};
 entries.set(key,e);return e;
}
doc.getElementById=element;doc.querySelector=selector=>element(selector);doc.querySelectorAll=()=>[];
let serial=0;doc.createElement=tag=>Object.assign(element('created-'+(++serial)),{tagName:tag});
const window={addEventListener(){}},location={protocol:'http:',hash:'#profiles'},calls=[];
const context={window,document:doc,location,URL,AbortController,setTimeout,clearTimeout,
 localStorage:{getItem(){return null},setItem(){}},fetch:async(url)=>{calls.push(url);assert.equal(url,'/local/v1/tabs');return{ok:true,status:200,json:async()=>snapshot()}}};
vm.createContext(context);vm.runInContext(tabSource,context);vm.runInContext(workspaceSource,context);
const app=window.TeamWorkspace.mount({icon:()=>'',esc:x=>String(x),notify:()=>{},managedRoute:()=>{},managedDiscover:async()=>{}});
Object.assign(app.model,{mode:'local',config:{mode:'local',api_base:'/local/v1',csrf_token:'synthetic'},
 profiles:[{...profile,name:'Synthetic profile',state:'running',selected:true,favorite:false,preset_id:'standard'}],
 selectedId:profile.id,presets:[],settings:{revision:1,tab_navigation:'side'}});
app.render();await settle();assert(!app.nativeTabs.state.active);
app.model.profileSection='activity';app.renderProfileDetail();await settle();assert(app.nativeTabs.state.active);assert(app.nativeTabs.state.snapshot);
location.hash='#resources';app.render();assert(!app.nativeTabs.state.active);assert.equal(app.nativeTabs.state.snapshot,null);
location.hash='#profiles';app.render();await settle();assert(app.nativeTabs.state.active);
app.showChoice();assert(!app.nativeTabs.state.active);assert.equal(app.nativeTabs.state.snapshot,null);
app.model.mode='local';app.render();await settle();assert(app.nativeTabs.state.active);
await app.chooseMode('managed');assert(!app.nativeTabs.state.active);assert.equal(app.nativeTabs.state.snapshot,null);
assert(calls.every(url=>url==='/local/v1/tabs'));
""")


class SyntheticHandle:
    def __init__(self):
        self.alive = True
        self.stops = 0

    def status(self):
        return ProcessStatus(self.alive, self.alive, safe_to_stop=True)

    def focus(self):
        return True

    def stop(self):
        self.stops += 1
        self.alive = False
        return True


class SyntheticAdapter:
    execution_kind = "synthetic"

    def __init__(self):
        self.handles = []

    def blockers(self, profile):
        return ()

    def start(self, context):
        handle = SyntheticHandle()
        self.handles.append(handle)
        return handle


class IndependentTabLoopbackTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.adapter = SyntheticAdapter()
        self.app = create_local_app(
            Path(self.directory.name) / "workspace", process_adapter=self.adapter
        )
        self.client = TestClient(
            self.app, base_url="http://127.0.0.1:8765", client=("127.0.0.1", 42310)
        )
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        self.token = self.client.get("/local/config").json()["csrf_token"]
        self.headers = {"X-Local-CSRF": self.token}
        self.body = {"tab_id": "tab_" + "9" * 32, "generation": 1, "expected_revision": 1}

    def test_tab_reads_reject_cross_origin_cross_site_and_duplicate_origin_before_metadata(self):
        with patch.object(self.app.state.coordinator, "selected_tabs") as read:
            for headers in (
                {"Origin": "http://localhost:8765"},
                {"Origin": "null"},
                {"Sec-Fetch-Site": "cross-site"},
                [("Origin", "http://127.0.0.1:8765"), ("Origin", "http://127.0.0.1:8765")],
                [("Host", "127.0.0.1:8765"), ("Host", "127.0.0.1:8765")],
            ):
                with self.subTest(headers=headers):
                    response = self.client.get("/local/v1/tabs", headers=headers)
                    self.assertEqual(response.status_code, 403)
            read.assert_not_called()

    def test_focus_requires_exact_json_csrf_and_forbids_url_method_and_script_fields(self):
        path = "/local/v1/profiles/local_review/tab-focus"
        with patch.object(self.app.state.coordinator, "focus_tab") as focus:
            self.assertEqual(self.client.post(path, json=self.body).status_code, 403)
            self.assertEqual(
                self.client.post(
                    path, content="{}", headers={**self.headers, "Content-Type": "text/plain"}
                ).status_code,
                415,
            )
            for extra in (
                {"method": "GET"},
                {"url": "https://elsewhere.test"},
                {"script": "private"},
            ):
                self.assertEqual(
                    self.client.post(
                        path, json={**self.body, **extra}, headers=self.headers
                    ).status_code,
                    422,
                )
            for key in ("generation", "expected_revision"):
                for value in (True, "1", None, 0, -1, 1.0):
                    self.assertEqual(
                        self.client.post(
                            path, json={**self.body, key: value}, headers=self.headers
                        ).status_code,
                        422,
                    )
            focus.assert_not_called()

    def test_profile_revision_selection_and_generation_fences_apply_through_http(self):
        first = self.app.state.workspace.create("First synthetic profile")["id"]
        second = self.app.state.workspace.create("Second synthetic profile")["id"]
        self.app.state.coordinator.action(first, "start")
        self.app.state.coordinator.action(second, "start")
        current = self.app.state.workspace.get(second)
        cases = (
            (
                second,
                {**self.body, "expected_revision": current["revision"] - 1},
                "revision_conflict",
            ),
            (
                first,
                {**self.body, "expected_revision": self.app.state.workspace.get(first)["revision"]},
                "selection_changed",
            ),
            (
                second,
                {**self.body, "expected_revision": current["revision"], "generation": 99},
                "stale_context",
            ),
        )
        for profile_id, body, code in cases:
            response = self.client.post(
                f"/local/v1/profiles/{profile_id}/tab-focus", json=body, headers=self.headers
            )
            self.assertGreaterEqual(response.status_code, 400)
            self.assertEqual(response.json()["detail"]["code"], code)
        self.assertTrue(all(handle.alive for handle in self.adapter.handles))

    def test_layout_and_mirror_patch_never_enters_eviction_path(self):
        profile = self.app.state.workspace.create("Synthetic resident")["id"]
        self.app.state.coordinator.action(profile, "start")
        settings = self.client.get("/local/v1/settings").json()
        with patch.object(
            self.app.state.coordinator, "_trim", side_effect=AssertionError("layout must not evict")
        ) as trim:
            response = self.client.patch(
                "/local/v1/settings",
                headers=self.headers,
                json={
                    "expected_revision": settings["revision"],
                    "profile_navigation": "grid",
                    "tab_navigation": "side",
                    "mirror_same_origin": True,
                },
            )
            self.assertEqual(response.status_code, 200)
            trim.assert_not_called()
        self.assertEqual(self.adapter.handles[0].stops, 0)
        self.assertTrue(self.app.state.coordinator._running[profile].lease.active)
        self.assertEqual(self.app.state.workspace.get(profile)["state"], "running")
