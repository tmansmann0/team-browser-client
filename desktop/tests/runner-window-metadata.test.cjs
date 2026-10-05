'use strict';
// Compile the production helper against fake CF/CG APIs. No native windows,
// Keychain, permissions, apps, or UI are accessed by these tests.
// Fixtures are adapted from permission-window-observer.test.cjs; that test and
// the acceptance observer are deliberately unchanged.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const source = path.resolve(__dirname, '../scripts/inspect-runner-windows.c');
const observerSource = path.resolve(__dirname, '../scripts/observe-permission-windows.c');
let temporary, executable, observer;

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
#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
enum { STRING = 1, NUMBER, DICTIONARY, ARRAY };
struct TestObject {
  int type, number, convertible;
  const char *text;
  CFTypeRef owner, title, layer, identifier, bounds;
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
  TestObject *bounds = object(DICTIONARY); bounds->width = 1440; bounds->height = 900; bounds->convertible = 1;
  result->bounds = bounds;
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
  rectangle->origin = (CGPoint){ -12345, 54321 };
  rectangle->size = (CGSize){ value->width, value->height }; return 1;
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
  if (!strcmp(key, kCGWindowBounds)) return value->bounds;
  if (!strcmp(key, kCGWindowNumber)) return value->identifier;
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
  const char *scenario = getenv("METADATA_TEST_CASE"); assert(scenario);
  if (!strcmp(scenario, "null_query")) return NULL;
  TestObject *result = object(ARRAY);
  result->items = calloc(512, sizeof(*result->items)); assert(result->items);
  TestObject *first = row("TeamBrowser", "TeamBrowser", 0, 100);
  result->items[0] = first; result->count = 1;
  if (!strcmp(scenario, "bad_query")) return test_string("not an array");
  if (!strcmp(scenario, "negative_count")) result->count = -1;
  else if (!strcmp(scenario, "missing_bounds")) first->bounds = NULL;
  else if (!strcmp(scenario, "bad_bounds")) first->bounds = number(7);
  else if (!strcmp(scenario, "unconvertible_bounds")) ((TestObject *)first->bounds)->convertible = 0;
  else if (!strcmp(scenario, "nonfinite_bounds")) { ((TestObject *)first->bounds)->width = NAN; ((TestObject *)first->bounds)->height = INFINITY; }
  else if (!strcmp(scenario, "out_of_range_bounds")) { ((TestObject *)first->bounds)->width = -1; ((TestObject *)first->bounds)->height = 65537; }
  else if (!strcmp(scenario, "zero_and_max_bounds")) { ((TestObject *)first->bounds)->width = 0; ((TestObject *)first->bounds)->height = 65536; }
  else if (!strcmp(scenario, "fractional_bounds")) { ((TestObject *)first->bounds)->width = 20.25; ((TestObject *)first->bounds)->height = 30.125; }
  else if (!strcmp(scenario, "empty_owner")) first->owner = test_string("");
  else if (!strcmp(scenario, "missing_all")) first->owner = first->title = first->layer = first->identifier = first->bounds = NULL;
  else if (!strcmp(scenario, "all_invalid")) first->owner = first->title = first->layer = first->identifier = first->bounds = number(7), first->layer = test_string("bad");
  else if (!strcmp(scenario, "sanitized_owner")) first->owner = test_string("Owner\"\n\t\001\177\303\251");
  else if (!strncmp(scenario, "path_owner:", 11)) first->owner = test_string(scenario+11);
  else if (!strcmp(scenario, "long_path_owner")) { char *owner = malloc(2048); assert(owner); memset(owner, 'A', 2000); strcpy(owner+2000, "/secret"); first->owner = test_string(owner); }
  else if (!strcmp(scenario, "large_output")) {
    char *owner = malloc(20001), *title = malloc(20001); assert(owner && title);
    memset(owner, 'A', 20000); owner[20000] = 0; memcpy(owner, "SecurityAgent", 13);
    memset(title, 'Z', 20000); title[20000] = 0; memcpy(title, "allow access", 12);
    result->count = 400;
    for (int i = 0; i < 400; i++) result->items[i] = row(owner, title, i % 2 ? INT_MAX : INT_MIN, 1000+i);
  }
  else if (!strcmp(scenario, "large_incomplete")) {
    result->count = 400;
    for (int i = 0; i < 400; i++) { TestObject *item = row(NULL, NULL, 0, 1000+i); item->layer = NULL; result->items[i] = item; }
  }
  else if (!strcmp(scenario, "exactly_32")) {
    result->count = 32;
    for (int i = 0; i < 32; i++) result->items[i] = row("Dock", NULL, 20, 1000+i);
  }
  else if (!strcmp(scenario, "empty_query")) result->count = 0;
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
  else assert(!strcmp(scenario, "normal_app"));
  return result;
}
`;

before(() => {
  temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'tbm-window-metadata-test-'));
  for (const directory of ['CoreFoundation', 'CoreGraphics']) {
    fs.mkdirSync(path.join(temporary, directory));
    fs.writeFileSync(path.join(temporary, directory, `${directory}.h`), header);
  }
  const stub = path.join(temporary, 'api-fixtures.c');
  fs.writeFileSync(stub, implementation);
  executable = path.join(temporary, 'metadata-fixture');
  observer = path.join(temporary, 'observer-fixture');
  for (const [input, output] of [[source, executable], [observerSource, observer]]) {
    const compiled = spawnSync('/usr/bin/cc', ['-std=c99', '-Wall', '-Wextra', '-Werror', '-I', temporary, input, stub, '-o', output], {
      encoding: 'utf8', timeout: 30000, maxBuffer: 65536,
    });
    assert.equal(compiled.error, undefined);
    assert.equal(compiled.signal, null);
    assert.equal(compiled.status, 0, compiled.stderr || 'Fixture compilation failed');
  }
});
after(() => { if (temporary) fs.rmSync(temporary, { recursive: true, force: true }); });

function runRaw(scenario, binary = executable) {
  const result = spawnSync(binary, [], {
    env: { METADATA_TEST_CASE: scenario }, encoding: 'utf8', timeout: 3000, maxBuffer: 16384,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.signal, null, result.stderr);
  assert.equal(result.status, ['null_query', 'bad_query', 'negative_count'].includes(scenario) ? 1 : 0, result.stderr);
  assert.equal(result.stderr, '');
  assert.ok(Buffer.byteLength(result.stdout) <= 16384);
  return result.stdout;
}
function run(scenario) { return JSON.parse(runRaw(scenario)); }
function first(scenario) { return run(scenario).rows[0]; }
function flagged(row, rule) { return row.guard_rules.includes(rule); }

// On uncapped valid queries, compare diagnostic labels with the unchanged
// production observer, including its conservative missing-metadata behavior.
function compareObserver(scenario) {
  const result = run(scenario);
  const expected = JSON.parse(runRaw(scenario, observer));
  const rules = result.rows.flatMap(row => row.guard_rules);
  assert.equal(result.status === 'ok', expected.query_ok, scenario);
  for (const rule of ['unexpected_window', 'security_ui_present', 'permission_title_observed']) {
    assert.equal(rules.includes(rule), expected[rule], `${scenario}: ${rule}`);
  }
  assert.equal(rules.includes('app_windows_exceeds_one'), expected.app_windows > 1, scenario);
}

test('compiled helper emits only the allowed fields and no title or window position', () => {
  const value = run('normal_app');
  assert.deepEqual(Object.keys(value), ['status', 'total', 'truncated', 'rows']);
  assert.equal(value.status, 'ok');
  assert.equal(value.total, 1);
  assert.equal(value.truncated, false);
  assert.deepEqual(value.rows, [{
    owner: 'TeamBrowser', layer: 0, width: 1440, height: 900,
    title_available: true, title_nonempty: true, permission_like_title: false, guard_rules: [],
  }]);
  compareObserver('normal_app');
});

for (const scenario of ['null_query', 'bad_query', 'negative_count']) {
  test(`compiled helper safely reports ${scenario}`, () => {
    assert.deepEqual(run(scenario), { status: 'query_failed', total: 0, truncated: false, rows: [] });
  });
}
test('empty query is explicitly incomplete rather than guard acceptance', () => {
  assert.deepEqual(run('empty_query'), { status: 'empty_query', total: 0, truncated: false, rows: [] });
});

for (const scenario of [
  'null_row', 'bad_row', 'missing_owner', 'bad_owner', 'missing_layer', 'bad_layer',
  'unconvertible_layer', 'missing_title', 'bad_title', 'empty_title', 'missing_all', 'all_invalid',
  'chrome_id_missing', 'chrome_id_bad', 'chrome_id_zero', 'chrome_id_negative', 'chrome_id_unconvertible',
]) test(`compiled helper labels missing/malformed metadata for ${scenario}`, () => {
  const result = run(scenario);
  assert.equal(result.status, 'metadata_incomplete');
  assert.ok(result.rows[0].guard_rules.some(rule => rule.startsWith('query_ok:')));
  compareObserver(scenario);
});

test('unavailable owner and layer are null rather than invented values', () => {
  const row = first('missing_all');
  assert.equal(row.owner, null);
  assert.equal(row.layer, null);
  assert.equal(row.title_available, false);
  assert.equal(row.title_nonempty, false);
  assert.ok(flagged(row, 'query_ok:missing_or_invalid_owner'));
  assert.ok(flagged(row, 'query_ok:missing_or_invalid_layer'));
});
test('empty string owner stays distinct from missing owner and remains unexpected', () => {
  const row = first('empty_owner');
  assert.equal(row.owner, '');
  assert.ok(flagged(row, 'unexpected_window'));
  assert.ok(!flagged(row, 'query_ok:missing_or_invalid_owner'));
  compareObserver('empty_owner');
});

for (const scenario of ['unknown_layer_zero', 'unknown_nonzero_layer', 'unknown_nonzero_missing_title', 'nonexact_chrome_owner']) {
  test(`compiled helper preserves unexpected-window rule for ${scenario}`, () => {
    assert.ok(flagged(first(scenario), 'unexpected_window'));
    compareObserver(scenario);
  });
}
for (const owner of ['Dock', 'Window Server', 'SystemUIServer']) {
  test(`compiled helper does not exempt ${owner} at layer zero`, () => {
    assert.ok(flagged(first(`chrome_layer_zero:${owner}`), 'unexpected_window'));
    compareObserver(`chrome_layer_zero:${owner}`);
  });
}
test('nonzero system chrome can have unavailable titles without becoming a dialog', () => {
  const result = run('chrome_only');
  assert.equal(result.status, 'ok');
  assert.equal(result.rows.length, 3);
  for (const row of result.rows) {
    assert.equal(row.title_available, false);
    assert.equal(row.title_nonempty, false);
    assert.deepEqual(row.guard_rules, []);
  }
  compareObserver('chrome_only');
});
test('additional app surfaces are labeled even at a nonzero layer', () => {
  const result = run('second_app_surface');
  assert.ok(result.rows.every(row => flagged(row, 'app_windows_exceeds_one')));
  compareObserver('second_app_surface');
});

for (const owner of ['SecurityAgent', 'CoreServicesUIAgent', 'UserNotificationCenter', 'authorizationhost', 'prefixSECURITYAGENTsuffix']) {
  test(`compiled helper labels security owner ${owner}`, () => {
    assert.ok(flagged(first(`security_owner:${owner}`), 'security_ui_present'));
    compareObserver(`security_owner:${owner}`);
  });
}
for (const title of ['KEYCHAIN', 'Permission', 'Enter password', 'App would like access', 'App wants to continue', 'Allow access']) {
  test(`compiled helper detects but never emits permission-like title ${title}`, () => {
    const scenario = `permission_title:${title} sensitive-sentinel /Users/private/path`;
    const raw = runRaw(scenario);
    const row = JSON.parse(raw).rows[0];
    assert.equal(row.permission_like_title, true);
    assert.ok(flagged(row, 'permission_title_observed'));
    assert.ok(!raw.includes(title));
    assert.ok(!raw.includes('sensitive-sentinel'));
    assert.ok(!raw.includes('/Users/private/path'));
    compareObserver(scenario);
  });
}

test('owner sanitizer removes JSON/control/non-ASCII hazards', () => {
  const raw = runRaw('sanitized_owner');
  const owner = JSON.parse(raw).rows[0].owner;
  assert.match(owner, /^Owner_+$/);
  assert.ok(!/[\x00-\x1f\x7f-\uffff]/.test(raw.trim()));
});
for (const owner of ['/Users/private/Application', 'C:\\private\\Application', 'disk:private:Application']) {
  test(`path-like owner is redacted: ${owner[0]}`, () => {
    const raw = runRaw(`path_owner:${owner}`);
    assert.equal(JSON.parse(raw).rows[0].owner, '[redacted-owner]');
    assert.ok(!raw.includes('private'));
  });
}
test('owner path detection also covers separators after the bounded prefix', () => {
  assert.equal(first('long_path_owner').owner, '[redacted-owner]');
});

for (const scenario of ['missing_bounds', 'bad_bounds', 'unconvertible_bounds', 'nonfinite_bounds', 'out_of_range_bounds']) {
  test(`unavailable or unsafe dimensions are null for ${scenario}`, () => {
    const result = run(scenario);
    assert.equal(result.rows[0].width, null);
    assert.equal(result.rows[0].height, null);
    assert.equal(result.status, 'ok');
    assert.deepEqual(result.rows[0].guard_rules, []);
    compareObserver(scenario);
  });
}
test('bounded zero, maximum, and fractional dimensions remain numeric', () => {
  assert.equal(first('zero_and_max_bounds').width, 0);
  assert.equal(first('zero_and_max_bounds').height, 65536);
  assert.equal(first('fractional_bounds').width, 20.25);
  assert.equal(first('fractional_bounds').height, 30.125);
});
for (const scenario of ['large_output', 'large_incomplete', 'chrome_overflow']) {
  test(`output remains valid, bounded, and visibly truncated for ${scenario}`, () => {
    const raw = runRaw(scenario);
    const value = JSON.parse(raw);
    assert.equal(value.total, 400);
    assert.equal(value.rows.length, 32);
    assert.equal(value.truncated, true);
    assert.ok(Buffer.byteLength(raw) <= 16384);
    assert.ok(!raw.includes('Z'.repeat(20)));
    for (const row of value.rows) {
      assert.ok(row.owner === null || Buffer.byteLength(row.owner) <= 64);
      assert.ok(row.layer === null || Number.isInteger(row.layer));
    }
    if (scenario === 'large_output') {
      assert.ok(value.rows.every(row => row.owner.length === 64 && row.permission_like_title));
      assert.equal(value.rows[0].layer, -2147483648);
      assert.equal(value.rows[1].layer, 2147483647);
    }
  });
}
test('exactly 32 rows are not falsely marked truncated', () => {
  const value = run('exactly_32');
  assert.equal(value.total, 32);
  assert.equal(value.rows.length, 32);
  assert.equal(value.truncated, false);
});
