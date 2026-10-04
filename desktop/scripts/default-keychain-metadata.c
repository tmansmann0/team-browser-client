// Reference metadata only. Intentionally does not open the database or query lock state.
// See docs/default-keychain-metadata.md for the excluded GetStatus call path.
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdio.h>

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1) return 64;
    SecKeychainRef keychain = NULL;
    const OSStatus copy_status = SecKeychainCopyDefault(&keychain);
    printf("{\"copy_default_status\":%d,\"default_reference_returned\":%s,"
           "\"lock_status_known\":false}\n",
           (int)copy_status, keychain != NULL ? "true" : "false");
    if (keychain != NULL) CFRelease(keychain);
    return 0;
}
