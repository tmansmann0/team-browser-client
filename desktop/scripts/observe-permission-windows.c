// Read-only window metadata. No accessibility grant, screen capture, or UI action.
#include <CoreGraphics/CoreGraphics.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <string.h>
static int contains(CFStringRef value, const char *needle) {
  if (!value || CFGetTypeID(value) != CFStringGetTypeID()) return 0;
  CFStringRef term = CFStringCreateWithCString(NULL, needle, kCFStringEncodingUTF8);
  int found = CFStringFind(value, term, kCFCompareCaseInsensitive).location != kCFNotFound;
  CFRelease(term); return found;
}
int main(void) {
  CFArrayRef rows = CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements, kCGNullWindowID);
  if (!rows) { puts("{\"query_ok\":false}"); return 1; }
  int security = 0, permission = 0, app_windows = 0, observable = CFArrayGetCount(rows) > 0, unexpected = 0;
  char chrome[2048] = ""; size_t used = 0;
  for (CFIndex i = 0; i < CFArrayGetCount(rows); i++) {
    CFDictionaryRef row = CFArrayGetValueAtIndex(rows, i);
    if (!row || CFGetTypeID(row) != CFDictionaryGetTypeID()) { observable = 0; continue; }
    CFStringRef owner = CFDictionaryGetValue(row, kCGWindowOwnerName);
    CFStringRef title = CFDictionaryGetValue(row, kCGWindowName);
    int layer = -1;
    CFNumberRef value = CFDictionaryGetValue(row, kCGWindowLayer);
    if (!owner || CFGetTypeID(owner) != CFStringGetTypeID() || !value || CFGetTypeID(value) != CFNumberGetTypeID() || !CFNumberGetValue(value, kCFNumberIntType, &layer)) observable = 0;
    int owner_ok = owner && CFGetTypeID(owner) == CFStringGetTypeID();
    int app = owner_ok && CFStringCompare(owner, CFSTR("TeamBrowser"), 0) == kCFCompareEqualTo;
    int desktop = owner_ok && (CFStringCompare(owner, CFSTR("Window Server"), 0) == kCFCompareEqualTo || CFStringCompare(owner, CFSTR("Dock"), 0) == kCFCompareEqualTo || CFStringCompare(owner, CFSTR("SystemUIServer"), 0) == kCFCompareEqualTo);
    if (desktop && layer != 0) {
      int window_id = 0;
      CFNumberRef identifier = CFDictionaryGetValue(row, kCGWindowNumber);
      if (!identifier || CFGetTypeID(identifier) != CFNumberGetTypeID() || !CFNumberGetValue(identifier, kCFNumberIntType, &window_id) || window_id <= 0) observable = 0;
      else {
        int added = snprintf(chrome + used, sizeof(chrome) - used, "%s\"%d:%d\"", used ? "," : "", window_id, layer);
        if (added < 0 || (size_t)added >= sizeof(chrome) - used) { observable = 0; break; }
        used += (size_t)added;
      }
    }
    if (app || !desktop || layer == 0) {
      if (!title || CFGetTypeID(title) != CFStringGetTypeID() || CFStringGetLength(title) == 0) observable = 0;
      if (!app) unexpected = 1;
    }
    if (contains(owner, "SecurityAgent") || contains(owner, "CoreServicesUIAgent") || contains(owner, "UserNotificationCenter") || contains(owner, "authorizationhost")) security = 1;
    if (contains(title, "keychain") || contains(title, "permission") || contains(title, "password") || contains(title, "would like") || contains(title, "wants to") || contains(title, "allow access")) permission = 1;
    if (app) app_windows++;
  }
  CFRelease(rows);
  printf("{\"query_ok\":%s,\"security_ui_present\":%s,\"permission_title_observed\":%s,\"unexpected_window\":%s,\"app_windows\":%d,\"chrome_signatures\":[%s]}\n", observable ? "true" : "false", security ? "true" : "false", permission ? "true" : "false", unexpected ? "true" : "false", app_windows, chrome);
  return 0;
}
