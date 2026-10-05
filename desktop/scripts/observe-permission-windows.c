// Read-only window metadata. No accessibility grant, screen capture, or UI action.
#include <CoreGraphics/CoreGraphics.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
static int contains(CFStringRef value, const char *needle) {
  if (!value || CFGetTypeID(value) != CFStringGetTypeID()) return 0;
  CFStringRef term = CFStringCreateWithCString(NULL, needle, kCFStringEncodingUTF8);
  int found = CFStringFind(value, term, kCFCompareCaseInsensitive).location != kCFNotFound;
  CFRelease(term); return found;
}
static uint64_t title_fingerprint(CFStringRef title) {
  uint64_t value = UINT64_C(14695981039346656037);
  for (CFIndex i = 0; i < CFStringGetLength(title); i++) {
    value ^= (uint64_t)CFStringGetCharacterAtIndex(title, i); value *= UINT64_C(1099511628211);
  }
  return value;
}
int main(void) {
  CFArrayRef rows = CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements, kCGNullWindowID);
  if (!rows) { puts("{\"query_ok\":false}"); return 1; }
  int security = 0, permission = 0, app_windows = 0, observable = CFArrayGetCount(rows) > 0, unexpected = 0;
  char chrome[2048] = "", menus[1024] = ""; size_t used = 0, menu_used = 0;
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
    // Only the exact menu-bar shapes observed in the read-only runner probe.
    // Freeze PID/window ID, dimensions and title fingerprint in the parent before launch.
    int menu = 0;
    int menu_owner = owner_ok && (CFStringCompare(owner, CFSTR("Control Center"), 0) == kCFCompareEqualTo || CFStringCompare(owner, CFSTR("Spotlight"), 0) == kCFCompareEqualTo);
    if (menu_owner) {
      CFTypeRef bounds = CFDictionaryGetValue(row, kCGWindowBounds);
      CGRect rectangle;
      int bounds_ok = bounds && CFGetTypeID(bounds) == CFDictionaryGetTypeID() && CGRectMakeWithDictionaryRepresentation((CFDictionaryRef)bounds, &rectangle);
      int title_ok = title && CFGetTypeID(title) == CFStringGetTypeID() && CFStringGetLength(title) > 0 && CFStringGetLength(title) <= 1024;
      if (!bounds_ok || !title_ok) observable = 0;
      if (bounds_ok && title_ok && layer == 25 && rectangle.size.height == 24 &&
          ((CFStringCompare(owner, CFSTR("Control Center"), 0) == kCFCompareEqualTo && (rectangle.size.width == 34 || rectangle.size.width == 147)) ||
           (CFStringCompare(owner, CFSTR("Spotlight"), 0) == kCFCompareEqualTo && rectangle.size.width == 31))) {
        int identifier = 0, pid = 0;
        CFNumberRef id_value = CFDictionaryGetValue(row, kCGWindowNumber);
        CFNumberRef pid_value = CFDictionaryGetValue(row, kCGWindowOwnerPID);
        if (!id_value || CFGetTypeID(id_value) != CFNumberGetTypeID() || !CFNumberGetValue(id_value,kCFNumberIntType,&identifier) || identifier <= 0 ||
            !pid_value || CFGetTypeID(pid_value) != CFNumberGetTypeID() || !CFNumberGetValue(pid_value,kCFNumberIntType,&pid) || pid <= 1) observable = 0;
        else {
          int added = snprintf(menus + menu_used, sizeof(menus) - menu_used, "%s\"%d:%d:%d:%d:%d:%016llx\"", menu_used ? "," : "", identifier, pid, layer, (int)rectangle.size.width, (int)rectangle.size.height, (unsigned long long)title_fingerprint(title));
          if (added < 0 || (size_t)added >= sizeof(menus) - menu_used) { observable = 0; break; }
          menu_used += (size_t)added; menu = 1;
        }
      }
    }
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
    if (!menu && (app || !desktop || layer == 0)) {
      if (!title || CFGetTypeID(title) != CFStringGetTypeID() || CFStringGetLength(title) == 0) observable = 0;
      if (!app) unexpected = 1;
    }
    if (contains(owner, "SecurityAgent") || contains(owner, "CoreServicesUIAgent") || contains(owner, "UserNotificationCenter") || contains(owner, "authorizationhost")) security = 1;
    if (contains(title, "keychain") || contains(title, "permission") || contains(title, "password") || contains(title, "would like") || contains(title, "wants to") || contains(title, "allow access")) permission = 1;
    if (app) app_windows++;
  }
  CFRelease(rows);
  printf("{\"query_ok\":%s,\"security_ui_present\":%s,\"permission_title_observed\":%s,\"unexpected_window\":%s,\"app_windows\":%d,\"chrome_signatures\":[%s],\"menu_signatures\":[%s]}\n", observable ? "true" : "false", security ? "true" : "false", permission ? "true" : "false", unexpected ? "true" : "false", app_windows, chrome, menus);
  return 0;
}
