// One read-only metadata snapshot; this is NOT an acceptance observer.
// No app launch, Keychain APIs, screenshot, accessibility, permission, or UI APIs.
// Compile: clang inspect-runner-windows.c -framework CoreGraphics -framework CoreFoundation
#include <CoreGraphics/CoreGraphics.h>
#include <CoreFoundation/CoreFoundation.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define MAX_ROWS 32
#define MAX_OWNER 64
#define MAX_OUTPUT 16384

struct window_row {
  char owner[MAX_OWNER + 1];
  int owner_available, layer, layer_available, title_available, title_nonempty;
  int invalid_row, invalid_owner, invalid_layer, invalid_chrome_id, required_title;
  int unexpected, security, permission, app;
  double width, height;
  int width_available, height_available;
};

static int is_type(CFTypeRef value, CFTypeID type) {
  return value && CFGetTypeID(value) == type;
}
static int contains(CFStringRef value, const char *needle) {
  if (!is_type(value, CFStringGetTypeID())) return 0;
  CFStringRef term = CFStringCreateWithCString(NULL, needle, kCFStringEncodingUTF8);
  if (!term) return 0;
  int found = CFStringFind(value, term, kCFCompareCaseInsensitive).location != kCFNotFound;
  CFRelease(term);
  return found;
}
static int equals(CFStringRef value, CFStringRef expected) {
  return is_type(value, CFStringGetTypeID()) && CFStringCompare(value, expected, 0) == kCFCompareEqualTo;
}
static int integer(CFTypeRef value, int *out) {
  return is_type(value, CFNumberGetTypeID()) && CFNumberGetValue(value, kCFNumberIntType, out);
}
static void sanitize_owner(CFStringRef owner, char result[MAX_OWNER + 1]) {
  // Never emit path-like owner metadata, even if the separator is past the cap.
  if (contains(owner, "/") || contains(owner, "\\") || contains(owner, ":")) {
    strcpy(result, "[redacted-owner]");
    return;
  }
  CFIndex length = CFStringGetLength(owner);
  if (length > MAX_OWNER) length = MAX_OWNER;
  for (CFIndex i = 0; i < length; i++) {
    UniChar ch = CFStringGetCharacterAtIndex(owner, i);
    result[i] = ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                 (ch >= '0' && ch <= '9') || ch == ' ' || ch == '.' ||
                 ch == '_' || ch == '-' || ch == '(' || ch == ')') ? (char)ch : '_';
  }
  result[length] = '\0';
}
static struct window_row inspect(CFTypeRef item) {
  struct window_row result = {0};
  result.layer = -1; // Match the existing observer's branching on invalid layers.
  if (!is_type(item, CFDictionaryGetTypeID())) { result.invalid_row = 1; return result; }
  CFDictionaryRef row = (CFDictionaryRef)item;
  CFStringRef owner = CFDictionaryGetValue(row, kCGWindowOwnerName);
  CFStringRef title = CFDictionaryGetValue(row, kCGWindowName);
  result.owner_available = is_type(owner, CFStringGetTypeID());
  result.layer_available = integer(CFDictionaryGetValue(row, kCGWindowLayer), &result.layer);
  result.invalid_owner = !result.owner_available;
  result.invalid_layer = !result.layer_available;
  result.title_available = is_type(title, CFStringGetTypeID());
  result.title_nonempty = result.title_available && CFStringGetLength(title) > 0;
  CFTypeRef bounds = CFDictionaryGetValue(row, kCGWindowBounds);
  CGRect rectangle;
  if (is_type(bounds, CFDictionaryGetTypeID()) && CGRectMakeWithDictionaryRepresentation((CFDictionaryRef)bounds, &rectangle)) {
    result.width = rectangle.size.width;
    result.height = rectangle.size.height;
    result.width_available = isfinite(result.width) && result.width >= 0 && result.width <= 65536;
    result.height_available = isfinite(result.height) && result.height >= 0 && result.height <= 65536;
  }
  if (result.owner_available) sanitize_owner(owner, result.owner);
  result.app = equals(owner, CFSTR("TeamBrowser"));
  int desktop = equals(owner, CFSTR("Window Server")) || equals(owner, CFSTR("Dock")) || equals(owner, CFSTR("SystemUIServer"));
  if (desktop && result.layer != 0) {
    int identifier = 0;
    result.invalid_chrome_id = !integer(CFDictionaryGetValue(row, kCGWindowNumber), &identifier) || identifier <= 0;
  }
  if (result.app || !desktop || result.layer == 0) {
    result.required_title = !result.title_nonempty;
    result.unexpected = !result.app;
  }
  result.security = contains(owner, "SecurityAgent") || contains(owner, "CoreServicesUIAgent") || contains(owner, "UserNotificationCenter") || contains(owner, "authorizationhost");
  result.permission = contains(title, "keychain") || contains(title, "permission") || contains(title, "password") || contains(title, "would like") || contains(title, "wants to") || contains(title, "allow access");
  return result;
}
static int append(char *buffer, size_t *used, const char *format, ...) {
  va_list args;
  va_start(args, format);
  int added = vsnprintf(buffer + *used, MAX_OUTPUT - *used, format, args);
  va_end(args);
  if (added < 0 || (size_t)added >= MAX_OUTPUT - *used) return 0;
  *used += (size_t)added;
  return 1;
}
static const char *boolean(int value) { return value ? "true" : "false"; }

int main(void) {
  CFArrayRef windows = CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements, kCGNullWindowID);
  if (!is_type(windows, CFArrayGetTypeID())) {
    if (windows) CFRelease(windows);
    puts("{\"status\":\"query_failed\",\"total\":0,\"truncated\":false,\"rows\":[]}");
    return 1;
  }
  CFIndex total = CFArrayGetCount(windows);
  if (total < 0) {
    CFRelease(windows);
    puts("{\"status\":\"query_failed\",\"total\":0,\"truncated\":false,\"rows\":[]}");
    return 1;
  }
  CFIndex count = total > MAX_ROWS ? MAX_ROWS : total;
  struct window_row rows[MAX_ROWS];
  int incomplete = 0, app_windows = 0;
  for (CFIndex i = 0; i < count; i++) {
    rows[i] = inspect(CFArrayGetValueAtIndex(windows, i));
    struct window_row *row = &rows[i];
    incomplete |= row->invalid_row || row->invalid_owner || row->invalid_layer || row->invalid_chrome_id || row->required_title;
    app_windows += row->app;
  }
  CFRelease(windows);

  // Assemble before writing so an output-limit failure still emits valid JSON.
  // The byte cap includes the trailing newline; output never contains raw titles.
  char output[MAX_OUTPUT];
  size_t used = 0;
  const char *status = !total ? "empty_query" : incomplete ? "metadata_incomplete" : "ok";
#define ADD(...) do { if (!append(output, &used, __VA_ARGS__)) goto output_limit; } while (0)
  ADD("{\"status\":\"%s\",\"total\":%lld,\"truncated\":%s,\"rows\":[", status, (long long)total, boolean(total > count));
  for (CFIndex i = 0; i < count; i++) {
    struct window_row *row = &rows[i];
    ADD("%s{\"owner\":", i ? "," : "");
    if (row->owner_available) ADD("\"%s\"", row->owner);
    else ADD("null");
    ADD(",\"layer\":");
    if (row->layer_available) ADD("%d", row->layer);
    else ADD("null");
    ADD(",\"width\":");
    if (row->width_available) ADD("%.3f", row->width);
    else ADD("null");
    ADD(",\"height\":");
    if (row->height_available) ADD("%.3f", row->height);
    else ADD("null");
    ADD(",\"title_available\":%s,\"title_nonempty\":%s,\"permission_like_title\":%s,\"guard_rules\":[", boolean(row->title_available), boolean(row->title_nonempty), boolean(row->permission));
    int rules = 0;
#define RULE(condition, name) do { if (condition) { ADD("%s\"%s\"", rules ? "," : "", name); rules++; } } while (0)
    RULE(row->invalid_row, "query_ok:invalid_row");
    RULE(row->invalid_owner, "query_ok:missing_or_invalid_owner");
    RULE(row->invalid_layer, "query_ok:missing_or_invalid_layer");
    RULE(row->invalid_chrome_id, "query_ok:missing_or_invalid_chrome_identifier");
    RULE(row->required_title, "query_ok:missing_or_empty_required_title");
    RULE(row->unexpected, "unexpected_window");
    RULE(row->security, "security_ui_present");
    RULE(row->permission, "permission_title_observed");
    RULE(row->app && app_windows > 1, "app_windows_exceeds_one");
#undef RULE
    ADD("]}");
  }
  ADD("]}\n");
#undef ADD
  // Rows are capped, so these labels do not assert anything about omitted rows,
  // transient windows, process absence, or a system-chrome baseline comparison.
  if (fwrite(output, 1, used, stdout) != used) return 1;
  return 0;
output_limit:
  puts("{\"status\":\"output_limit\",\"total\":0,\"truncated\":true,\"rows\":[]}");
  return 1;
}
