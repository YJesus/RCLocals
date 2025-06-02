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

·**Rogue namespaces**

·**Hashing binaries and libs + searching in CYMRU malware hash registry https://team-cymru.com/community-services/mhr/** 

## REQUIREMENTS 

Debian/Ubuntu and derivatives: install debsums # apt-get install debsums

All platforms: pay attention to non default Python modules (colorama and DNS) 

## USAGE

  Basic scan (only suspicious findings)
  
  python3 rclocals.py --triage

  Full detailed scan (all information)
  
  python3 rclocals.py --all

  Run specific tests (individual modules):
  
  python3 rclocals.py --test <test_name>

Available individual tests:

  TestGPG         - Check GPG keys and signatures
  
  TestPackages    - Verify installed packages integrity
  
  TestFileInt     - Check file and process integrity
  
  TestSpoofed     - Detect processes with spoofed names
  
  TestCron        - Analyze cron entries and jobs
  
  TestRC          - Check system and user RC files
  
  TestX           - Examine X system startup files
  
  TestSystemd     - Inspect systemd units and timers
  
  TestTMP         - Check tmpfiles.d configurations
  
  TestHash        - Hash and verify critical binaries
  
  TestMount       - Detect processes with private mounts
  

Examples:

  python3 rclocals.py --test TestCron
  
  python3 rclocals.py --test TestHash
  

## Screenshots

![Keys and packages](https://github.com/YJesus/RCLocals/blob/master/screenshots/1.jpg)

![File integrity](https://github.com/YJesus/RCLocals/blob/master/screenshots/2.png)

![Process integrity](https://github.com/YJesus/RCLocals/blob/master/screenshots/3.png)

![Process integrity](https://github.com/YJesus/RCLocals/blob/master/screenshots/4.png)
