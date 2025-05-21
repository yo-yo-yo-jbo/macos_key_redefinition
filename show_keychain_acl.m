/**************************************************************************
 *                                                                        *
 *  File:       show_keychain_acl.m                                       *
 *  Purpose:    Presents the ACLs of a given keychain item.               *
 *                                                                        *
 **************************************************************************/

#import <Foundation/Foundation.h>
#import <Security/Security.h>

// Suppress deprecation warnings for legacy Security APIs
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

/**************************************************************************
 *                                                                        *
 *  Macro:      SAFE_RELEASE                                              *
 *  Purpose:    Safely releases an object with CFRelease unless NULL.     *
 *  Parameters: - obj - the object.                                       *
 *                                                                        *
 **************************************************************************/
#define SAFE_RELEASE(obj)       do                          \
                                {                           \
                                    if (NULL != (obj))      \
                                    {                       \
                                        CFRelease(obj);     \
                                        (obj) = NULL;       \
                                    }                       \
                                }                           \
                                while (0)

/**************************************************************************
 *                                                                        *
 *  Function:   print_acl_for_service                                     *
 *  Purpose:    Prints out all ACLs for a given service name.             *
 *  Parameters: - service - the service name.                             *
 *  Remarks:    - Best-effort.                                            *
 *              - Works on the default keychain only.                     *
 *              - Uses deprecated APIs.                                   *
 *                                                                        *
 **************************************************************************/
static
void
print_acl_for_service(
    NSString* service
)
{
    OSStatus status = errSecSuccess;
    SecKeychainItemRef item_ref = NULL;
    SecAccessRef access_ref = NULL;
    CFArrayRef acl_list = NULL;
    CFIndex acl_counter = 0;
    CFIndex app_counter = 0;
    SecACLRef curr_acl = NULL;
    CFArrayRef trusted_apps = NULL;
    CFStringRef description = NULL;
    SecKeychainPromptSelector prompt_selector = 0;
    SecTrustedApplicationRef app_ref = NULL;
    CFDataRef app_data = NULL;
    NSString* path = NULL;

    // Find the item
    status = SecKeychainFindGenericPassword(
        NULL,
        (UInt32)[service length],
        [service UTF8String],
        0,
        NULL,
        NULL,
        NULL,
        &item_ref
    );
    if ((errSecSuccess != status) || (NULL == item_ref))
    {
        NSLog(@"[!] Could not find keychain item: %d", (int)status);
        goto cleanup;
    }

    // Get thew access reference
    status = SecKeychainItemCopyAccess(item_ref, &access_ref);
    if ((errSecSuccess != status) || (NULL == access_ref))
    {
        NSLog(@"[!] Could not copy access for item: %d", (int)status);
        goto cleanup;
    }

    // Get the ACL list
    status = SecAccessCopyACLList(access_ref, &acl_list);
    if ((errSecSuccess != status) || (NULL == acl_list))
    {
        NSLog(@"[!] Failed to get ACL list: %d", (int)status);
        goto cleanup;
    }

    // Print ACLs
    NSLog(@"[+] ACLs for '%@':", service);
    for (acl_counter = 0; acl_counter < CFArrayGetCount(acl_list); acl_counter++)
    {
        // Get current ACL
        curr_acl = (SecACLRef)CFArrayGetValueAtIndex(acl_list, acl_counter);

        // Copy ACL contents (best-effort)
        SAFE_RELEASE(trusted_apps);
        SAFE_RELEASE(description);
        status = SecACLCopyContents(curr_acl, &trusted_apps, &description, &prompt_selector);
        if (errSecSuccess != status)
        {
            NSLog(@"    [!] Failed to read ACL #%ld", acl_counter + 1);
            continue;
        }

        // Print description
        NSLog(@"  [ACL #%ld]", acl_counter + 1);
        if (NULL != description)
        {
            NSLog(@"    Description: %@", description);
        }
        else
        {
            NSLog(@"    Description: <none>");
        }

        // Print prompt selector
        NSLog(@"    Prompt Selector: %u", prompt_selector);

        // Print trusted Apps
        if ((NULL != trusted_apps) && (0 < CFArrayGetCount(trusted_apps)))
        {
            // Iterate all trusted Apps
            NSLog(@"    Trusted Applications:");
            for (app_counter = 0; app_counter < CFArrayGetCount(trusted_apps); app_counter++)
            {
                // Get the current App
                app_ref = (SecTrustedApplicationRef)CFArrayGetValueAtIndex(trusted_apps, app_counter);

                // Get the trusted App data (best-effort)
                SAFE_RELEASE(app_data);
                status = SecTrustedApplicationCopyData(app_ref, &app_data);
                if ((errSecSuccess == status) && (NULL != app_data))
                {
                    path = [[NSString alloc]initWithData:(__bridge NSData *)app_data encoding:NSUTF8StringEncoding];
                    if (path.length > 0)
                    {
                        NSLog(@"      - %@", path);
                    }
                    else
                    {
                        NSLog(@"      - <binary blob>");
                    }
                } else {
                    NSLog(@"      - <unknown>");
                }
            }
        }
        else
        {
            NSLog(@"    Trusted Applications: <none>");
        }
    }

cleanup:

    // Free resources
    SAFE_RELEASE(app_data);
    SAFE_RELEASE(trusted_apps);
    SAFE_RELEASE(description);
    SAFE_RELEASE(acl_list);
    SAFE_RELEASE(access_ref);
    SAFE_RELEASE(item_ref);
}
#pragma clang diagnostic pop

/**************************************************************************
 *                                                                        *
 *  Function:   main                                                      *
 *  Purpose:    Main routine.                                             *
 *  Parameters: - argc - The number of arguments.                         *
 *              - argv - The single argument of the service name.         *
 *  Returns:    0 on success, non-zero upon failure.                      *
 *                                                                        *
 **************************************************************************/
int
main(
    int argc,
    const char* argv[]
)
{
    @autoreleasepool
    {
        if (argc != 2)
        {
            NSLog(@"Usage: %s <ServiceName>", argv[0]);
            return 1;
        }
        NSString* service_name = [NSString stringWithUTF8String:argv[1]];
        print_acl_for_service(service_name);
    }
    return 0;
}

