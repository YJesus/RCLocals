# RCLocals
Inspired by 'Autoruns' from Sysinternals, RCLocals analyzes all Linux startup possibilities to find backdoors, also performs process integrity verification, scan for DLL injected processes and much more

## Things covered:
·**List GPG keys trusted by the system**

·**Installed Packages**

·**File integrity**

·**Process integrity** (process and libraries loaded in a process that not belongs to any installed package)

·**Processes with name spoofed** (processes that use prctl() to change their name in /bin/ps)

·**CRON entries**

·**RC files**

·**X system startup files**

·**Active Systemd Units**

·**Systemd Timer Units**

·**tmpfiles.d**

·**linger users**

·**Hashing binaries and libs + searching in CYMRU malware hash registry https://team-cymru.com/community-services/mhr/** 

## REQUIREMENTS 

Debian/Ubuntu and derivatives: install debsums # apt-get install debsums

All platforms: pay attention to non default Python modules (colorama and DNS) 

## USAGE

For only suspicious information:

#python3 rclocals.py --triage

For detailed information:

#python3 rclocals.py --all 

## Screenshots

![Keys and packages](https://github.com/YJesus/RCLocals/blob/master/screenshots/1.jpg)

![File integrity](https://github.com/YJesus/RCLocals/blob/master/screenshots/2.png)

![Process integrity](https://github.com/YJesus/RCLocals/blob/master/screenshots/3.png)

![Process integrity](https://github.com/YJesus/RCLocals/blob/master/screenshots/4.png)
