'use strict';
// Execute the unchanged C observer against compile-time API fixtures only.
// These tests do not access macOS windows, Keychain, permission APIs, or user data.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { assertWindowObservation } = require('../scripts/compare-normal-home.cjs');

const source = path.resolve(__dirname, '../scripts/observe-permission-windows.c');
let temporary, executable;

const header = String.raw`
#ifndef TEST_CF_STUB_H
#define TEST_CF_STUB_H
#include <stddef.h>
typedef long CFIndex;
typedef unsigned short UniChar;
typedef struct { double width, height; } CGSize;
typedef struct { double x, y; } CGPoint;
typedef struct { CGPoint origin; CGSize size; } CGRect;
typedef unsigned long CFTypeID;
typedef struct TestObject TestObject;
typedef const TestObject *CFTypeRef;
typedef CFTypeRef CFArrayRef;
typedef CFTypeRef CFDictionaryRef;
typedef CFTypeRef CFStringRef;
typedef CFTypeRef CFNumberRef;
typedef struct { CFIndex location; CFIndex length; } CFRange;
enum { kCFStringEncodingUTF8 = 1, kCFCompareCaseInsensitive = 1,
  kCFCompareEqualTo = 0, kCFNumberIntType = 1, kCFNotFound = -1,
  kCGWindowListOptionOnScreenOnly = 1, kCGWindowListExcludeDesktopElements = 2,
  kCGNullWindowID = 0 };
#define kCGWindowOwnerName "owner"
#define kCGWindowName "title"
#define kCGWindowLayer "layer"
#define kCGWindowNumber "number"
#define kCGWindowBounds "bounds"
#define kCGWindowOwnerPID "pid"
#define CFSTR(value) test_string(value)
CFStringRef test_string(const char *value);
CFTypeID CFGetTypeID(CFTypeRef value);
CFTypeID CFStringGetTypeID(void);
CFTypeID CFNumberGetTypeID(void);
CFTypeID CFDictionaryGetTypeID(void);
CFTypeID CFArrayGetTypeID(void);
UniChar CFStringGetCharacterAtIndex(CFStringRef value, CFIndex index);
int CGRectMakeWithDictionaryRepresentation(CFDictionaryRef value, CGRect *rectangle);
CFStringRef CFStringCreateWithCString(const void *allocator, const char *text, int encoding);
CFRange CFStringFind(CFStringRef value, CFStringRef term, int flags);
int CFStringCompare(CFStringRef left, CFStringRef right, int flags);
CFIndex CFStringGetLength(CFStringRef value);
void CFRelease(CFTypeRef value);
CFIndex CFArrayGetCount(CFArrayRef value);
const void *CFArrayGetValueAtIndex(CFArrayRef value, CFIndex index);
const void *CFDictionaryGetValue(CFDictionaryRef value, const void *key);
int CFNumberGetValue(CFNumberRef value, int type, void *out);
CFArrayRef CGWindowListCopyWindowInfo(int options, int relative);
#endif
`;

const implementation = String.raw`
#include "CoreFoundation/CoreFoundation.h"
#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
enum { STRING = 1, NUMBER, DICTIONARY, ARRAY };
struct TestObject {
  int type, number, convertible;
  const char *text;
  CFTypeRef owner, title, layer, identifier, bounds, pid;
  double width, height;
  CFTypeRef *items;
  CFIndex count;
};
static TestObject *object(int type) {
  TestObject *result = calloc(1, sizeof(*result));
  assert(result); result->type = type; return result;
}
CFStringRef test_string(const char *value) {
  TestObject *result = object(STRING); result->text = value; return result;
}
static CFNumberRef number(int value) {
  TestObject *result = object(NUMBER); result->number = value; result->convertible = 1; return result;
}
static TestObject *row(const char *owner, const char *title, int layer, int identifier) {
  TestObject *result = object(DICTIONARY);
  result->owner = owner ? test_string(owner) : NULL;
  result->title = title ? test_string(title) : NULL;
  TestObject *bounds = object(DICTIONARY); bounds->width = 1024; bounds->height = 768; bounds->convertible = 1;
  result->bounds = bounds; result->pid = number(200);
  result->layer = number(layer); result->identifier = number(identifier); return result;
}
CFTypeID CFGetTypeID(CFTypeRef value) { assert(value); return (CFTypeID)value->type; }
CFTypeID CFArrayGetTypeID(void) { return ARRAY; }
CFTypeID CFStringGetTypeID(void) { return STRING; }
CFTypeID CFNumberGetTypeID(void) { return NUMBER; }
CFTypeID CFDictionaryGetTypeID(void) { return DICTIONARY; }
CFStringRef CFStringCreateWithCString(const void *allocator, const char *text, int encoding) {
  (void)allocator; assert(encoding == kCFStringEncodingUTF8); return test_string(text);
}
CFRange CFStringFind(CFStringRef value, CFStringRef term, int flags) {
  assert(value && value->type == STRING && term && term->type == STRING);
  assert(flags == kCFCompareCaseInsensitive);
  const size_t haystack = strlen(value->text), needle = strlen(term->text);
  for (size_t i = 0; i + needle <= haystack; i++) {
    size_t j = 0;
    while (j < needle && tolower((unsigned char)value->text[i+j]) == tolower((unsigned char)term->text[j])) j++;
    if (j == needle) return (CFRange){ (CFIndex)i, (CFIndex)needle };
  }
  return (CFRange){ kCFNotFound, 0 };
}
int CFStringCompare(CFStringRef left, CFStringRef right, int flags) {
  assert(left && left->type == STRING && right && right->type == STRING);
  assert(flags == 0); return strcmp(left->text, right->text);
}
CFIndex CFStringGetLength(CFStringRef value) {
  assert(value && value->type == STRING); return (CFIndex)strlen(value->text);
}
UniChar CFStringGetCharacterAtIndex(CFStringRef value, CFIndex index) {
  assert(value && value->type == STRING && index >= 0 && index < CFStringGetLength(value));
  return (unsigned char)value->text[index];
}
int CGRectMakeWithDictionaryRepresentation(CFDictionaryRef value, CGRect *rectangle) {
  assert(value && value->type == DICTIONARY);
  if (!value->convertible) return 0;
  rectangle->origin = (CGPoint){0,0}; rectangle->size = (CGSize){value->width,value->height}; return 1;
}
void CFRelease(CFTypeRef value) { (void)value; }
CFIndex CFArrayGetCount(CFArrayRef value) { assert(value && value->type == ARRAY); return value->count; }
const void *CFArrayGetValueAtIndex(CFArrayRef value, CFIndex index) {
  assert(value && value->type == ARRAY && index >= 0 && index < value->count); return value->items[index];
}
const void *CFDictionaryGetValue(CFDictionaryRef value, const void *key) {
  assert(value && value->type == DICTIONARY);
  if (!strcmp(key, kCGWindowOwnerName)) return value->owner;
  if (!strcmp(key, kCGWindowName)) return value->title;
  if (!strcmp(key, kCGWindowLayer)) return value->layer;
  if (!strcmp(key, kCGWindowNumber)) return value->identifier;
  if (!strcmp(key, kCGWindowBounds)) return value->bounds;
  if (!strcmp(key, kCGWindowOwnerPID)) return value->pid;
  assert(0); return NULL;
}
int CFNumberGetValue(CFNumberRef value, int type, void *out) {
  assert(value && value->type == NUMBER && type == kCFNumberIntType);
  if (!value->convertible) return 0;
  *(int *)out = value->number; return 1;
}
CFArrayRef CGWindowListCopyWindowInfo(int options, int relative) {
  assert(options == (kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements));
  assert(relative == kCGNullWindowID);
  const char *scenario = getenv("OBSERVER_TEST_CASE"); assert(scenario);
  if (!strcmp(scenario, "null_query")) return NULL;
  TestObject *result = object(ARRAY);
  result->items = calloc(512, sizeof(*result->items)); assert(result->items);
  TestObject *first = row("TeamBrowser", "TeamBrowser", 0, 100);
  result->items[0] = first; result->count = 1;
  if (!strcmp(scenario, "empty_query")) result->count = 0;
  else if (!strcmp(scenario, "null_row")) result->items[0] = NULL;
  else if (!strcmp(scenario, "bad_row")) result->items[0] = test_string("not a dictionary");
  else if (!strcmp(scenario, "missing_owner")) first->owner = NULL;
  else if (!strcmp(scenario, "bad_owner")) first->owner = number(7);
  else if (!strcmp(scenario, "missing_layer")) first->layer = NULL;
  else if (!strcmp(scenario, "bad_layer")) first->layer = test_string("zero");
  else if (!strcmp(scenario, "unconvertible_layer")) ((TestObject *)first->layer)->convertible = 0;
  else if (!strcmp(scenario, "missing_title")) first->title = NULL;
  else if (!strcmp(scenario, "bad_title")) first->title = number(7);
  else if (!strcmp(scenario, "empty_title")) first->title = test_string("");
  else if (!strcmp(scenario, "unknown_layer_zero")) first->owner = test_string("Finder");
  else if (!strcmp(scenario, "unknown_nonzero_layer")) { first->owner = test_string("UnknownPromptHost"); first->layer = number(8); }
  else if (!strcmp(scenario, "unknown_nonzero_missing_title")) { first->owner = test_string("UnknownPromptHost"); first->layer = number(8); first->title = NULL; }
  else if (!strcmp(scenario, "nonexact_chrome_owner")) { first->owner = test_string("Some Dock Helper"); first->layer = number(20); }
  else if (!strcmp(scenario, "second_app_surface")) { result->items[1] = row("TeamBrowser", "TeamBrowser", 8, 101); result->count = 2; }
  else if (!strcmp(scenario, "chrome_only")) {
    result->items[0] = row("Dock", NULL, 20, 200);
    result->items[1] = row("Window Server", NULL, 24, 201);
    result->items[2] = row("SystemUIServer", NULL, 25, 202); result->count = 3;
  }
  else if (!strcmp(scenario, "chrome_overflow")) {
    result->count = 400;
    for (int i = 0; i < 400; i++) result->items[i] = row("Dock", NULL, 20, 1000+i);
  }
  else if (!strncmp(scenario, "chrome_id_", 10)) {
    first->owner = test_string("Dock"); first->title = NULL; first->layer = number(20);
    if (!strcmp(scenario, "chrome_id_missing")) first->identifier = NULL;
    else if (!strcmp(scenario, "chrome_id_bad")) first->identifier = test_string("100");
    else if (!strcmp(scenario, "chrome_id_zero")) first->identifier = number(0);
    else if (!strcmp(scenario, "chrome_id_negative")) first->identifier = number(-5);
    else if (!strcmp(scenario, "chrome_id_unconvertible")) ((TestObject *)first->identifier)->convertible = 0;
    else assert(0);
  }
  else if (!strncmp(scenario, "chrome_layer_zero:", 18)) first->owner = test_string(scenario+18);
  else if (!strncmp(scenario, "security_owner:", 15)) { first->owner = test_string(scenario+15); first->layer = number(8); }
  else if (!strncmp(scenario, "permission_title:", 17)) first->title = test_string(scenario+17);
  else if (!strncmp(scenario, "menu_", 5)) {
    first->owner=test_string("Control Center");first->title=test_string("Menu Item");first->layer=number(25);
    ((TestObject *)first->bounds)->width=34;((TestObject *)first->bounds)->height=24;
    if(!strcmp(scenario,"menu_control34")) {}
    else if(!strcmp(scenario,"menu_control147")) ((TestObject *)first->bounds)->width=147;
    else if(!strcmp(scenario,"menu_spotlight31")) {first->owner=test_string("Spotlight");((TestObject *)first->bounds)->width=31;}
    else if(!strcmp(scenario,"menu_wrong_width")) ((TestObject *)first->bounds)->width=35;
    else if(!strcmp(scenario,"menu_wrong_height")) ((TestObject *)first->bounds)->height=25;
    else if(!strcmp(scenario,"menu_wrong_layer")) first->layer=number(0);
    else if(!strcmp(scenario,"menu_missing_bounds")) first->bounds=NULL;
    else if(!strcmp(scenario,"menu_bad_bounds")) first->bounds=test_string("bounds");
    else if(!strcmp(scenario,"menu_missing_title")) first->title=NULL;
    else if(!strcmp(scenario,"menu_permission_title")) first->title=test_string("Keychain permission");
    else if(!strcmp(scenario,"menu_missing_pid")) first->pid=NULL;
    else if(!strcmp(scenario,"menu_bad_pid")) first->pid=number(1);
    else if(!strcmp(scenario,"menu_missing_id")) first->identifier=NULL;
    else if(!strcmp(scenario,"menu_long_title")) {char *text=calloc(1026,1);memset(text,'A',1025);first->title=test_string(text);}
    else if(!strcmp(scenario,"menu_four")) {
      result->count=4;
      for(int i=1;i<4;i++) {TestObject *item=row("Control Center","Menu Item",25,100+i);((TestObject*)item->bounds)->width=34;((TestObject*)item->bounds)->height=24;result->items[i]=item;}
    }
    else assert(0);
  }
  else assert(!strcmp(scenario, "normal_app"));
  return result;
}
`;

before(() => {
  temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'tbm-window-observer-test-'));
  for (const directory of ['CoreFoundation', 'CoreGraphics']) {
    fs.mkdirSync(path.join(temporary, directory));
    fs.writeFileSync(path.join(temporary, directory, `${directory}.h`), header);
  }
  const stub = path.join(temporary, 'api-fixtures.c');
  fs.writeFileSync(stub, implementation);
  executable = path.join(temporary, 'observer-fixture');
  const compiled = spawnSync('/usr/bin/cc', ['-std=c99', '-Wall', '-Wextra', '-Werror', '-I', temporary, source, stub, '-o', executable], {
    encoding: 'utf8', timeout: 30000, maxBuffer: 65536,
  });
  assert.equal(compiled.error, undefined);
  assert.equal(compiled.signal, null);
  assert.equal(compiled.status, 0, compiled.stderr || 'Fixture compilation failed');
});

after(() => { if (temporary) fs.rmSync(temporary, { recursive: true, force: true }); });

function runRaw(scenario) {
  const result = spawnSync(executable, [], {
    env: { OBSERVER_TEST_CASE: scenario }, encoding: 'utf8', timeout: 3000, maxBuffer: 4096,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.signal, null, result.stderr);
  assert.equal(result.status, scenario === 'null_query' ? 1 : 0, result.stderr);
  assert.equal(result.stderr, '');
  return result.stdout;
}
function run(scenario) { return JSON.parse(runRaw(scenario)); }

test('compiled C accepts a single observable TeamBrowser surface', () => {
  const value = run('normal_app');
  assertWindowObservation(value, true, []);
  assert.equal(value.app_windows, 1);
});

for (const scenario of [
  'null_query', 'empty_query', 'null_row', 'bad_row', 'missing_owner', 'bad_owner',
  'missing_layer', 'bad_layer', 'unconvertible_layer', 'missing_title', 'bad_title', 'empty_title',
  'chrome_id_missing', 'chrome_id_bad', 'chrome_id_zero', 'chrome_id_negative', 'chrome_id_unconvertible',
]) test(`compiled C fails closed on ${scenario}`, () => {
  const value = run(scenario);
  assert.equal(value.query_ok, false);
  assert.throws(() => assertWindowObservation(value));
});

for (const scenario of ['unknown_layer_zero', 'unknown_nonzero_layer', 'unknown_nonzero_missing_title', 'nonexact_chrome_owner']) {
  test(`compiled C rejects unexpected owner for ${scenario}`, () => {
    const value = run(scenario);
    assert.equal(value.unexpected_window, true);
    assert.throws(() => assertWindowObservation(value));
  });
}

for (const owner of ['Dock', 'Window Server', 'SystemUIServer']) {
  test(`compiled C does not exempt ${owner} at normal layer`, () => {
    const value = run(`chrome_layer_zero:${owner}`);
    assert.equal(value.unexpected_window, true);
    assert.throws(() => assertWindowObservation(value));
  });
}

test('compiled C counts an additional TeamBrowser sheet at a nonzero layer', () => {
  const value = run('second_app_surface');
  assert.equal(value.app_windows, 2);
  assert.throws(() => assertWindowObservation(value));
});

test('compiled C permits only stable, identified nonzero-layer system chrome', () => {
  const value = run('chrome_only');
  assert.deepEqual(value.chrome_signatures, ['200:20', '201:24', '202:25']);
  assertWindowObservation(value, false, value.chrome_signatures);
  assert.throws(() => assertWindowObservation(value, true, value.chrome_signatures));
  assert.throws(() => assertWindowObservation(value, false, ['200:20', '201:24']));
});

test('overflowing chrome metadata cannot become an accepted observation', () => {
  const raw = runRaw('chrome_overflow');
  assert.ok(Buffer.byteLength(raw) <= 4096);
  assert.throws(() => assertWindowObservation(JSON.parse(raw)));
});

for (const owner of ['SecurityAgent', 'CoreServicesUIAgent', 'UserNotificationCenter', 'authorizationhost']) {
  test(`compiled C rejects security owner ${owner}`, () => {
    const value = run(`security_owner:${owner}`);
    assert.equal(value.security_ui_present, true);
    assert.throws(() => assertWindowObservation(value));
  });
}

for (const title of ['KEYCHAIN', 'Permission', 'Enter password', 'App would like access', 'App wants to continue', 'Allow access']) {
  test(`compiled C rejects permission-like title ${title}`, () => {
    const value = run(`permission_title:${title}`);
    assert.equal(value.permission_title_observed, true);
    assert.throws(() => assertWindowObservation(value));
  });
}

for(const name of ['menu_control34','menu_control147','menu_spotlight31']) test(`compiled C accepts only observed menu shape ${name}`,()=>{
 const value=run(name);assert.equal(value.menu_signatures.length,1);assertWindowObservation(value,false,[],value.menu_signatures);
});
for(const name of ['menu_wrong_width','menu_wrong_height','menu_wrong_layer','menu_missing_bounds','menu_bad_bounds','menu_missing_title','menu_permission_title','menu_missing_pid','menu_bad_pid','menu_missing_id','menu_long_title','menu_four']) test(`compiled C fails closed on altered menu ${name}`,()=>assert.throws(()=>assertWindowObservation(run(name))));
