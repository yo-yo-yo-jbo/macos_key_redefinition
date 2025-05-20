# On the dangers of key redefinition attacks on macOS
Earlier this year I released a [blogpost](https://www.microsoft.com/en-us/security/blog/2025/05/01/analyzing-cve-2025-31191-a-macos-security-scoped-bookmarks-based-sandbox-escape/) detailing a macOS Sandbox Escape vulnerability I discovered, and got tracked as [CVE-2025-31191](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-31191).  
In this blogpost I want to share further thoughts about the class of attacks I uncovered, and how offensive security folks might use those.  

## Background - the Keychain
The [macOS Keychain](https://support.apple.com/guide/keychain-access/what-is-keychain-access-kyca1083/mac) is Apple’s secure storage system for sensitive user data, such as passwords, private keys, certificates, and secure notes.  
It is implemented as a set of SQLite-based keychain files (like `login.keychain-db`, `System.keychain`, etc.), each serving different scopes—personal, system-wide, or session-based.  
Items within a keychain are encrypted using per-item keys, which are in turn wrapped by a class key protected by the user’s login credentials and, depending on the item class, the [Secure Enclave](https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web).  
Keychains support various item types, including generic passwords, internet passwords, cryptographic keys, and certificates.  
Access to these items is finely controlled using Access Control Lists (ACLs), which define what apps or processes can retrieve or modify specific entries.  
ACLs can enforce user presence (e.g., via Touch ID) or restrict access to a particular binary, offering strong per-item access guarantees in both GUI and command-line contexts.

### The structure of keychain files
Keychain files are located as physical files on the device:
- User keychains (like `login.keychain-db`) are stored at `~/Library/Keychains/`. Each user has their own folder here, often with a UUID-named subdirectory containing their keychains.
- System keychain is located at `/Library/Keychains/System.keychain`.
- System Root Certificates keychain (read-only, trusted root CAs) are at `/System/Library/Keychains/SystemRootCertificates.keychain`.
- iCloud keychain items are synced across devices and encrypted end-to-end, but locally cached data may reside in the user's keychain directory with additional protections.

Let's examine the structure of a user keychain:
