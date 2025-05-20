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
