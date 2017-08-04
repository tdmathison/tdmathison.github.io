---
layout: post
title: "Tips and Tricks"
categories: guides_docs
excerpt: Tips and Tricks
comments: false
share: true
tags: [tips-and-tricks, hacking]
image:
  feature:
date: 2017-07-17
modified: 2017-08-03
---
# Some things I have ran into and my solution around them

# List
1. [Slow Kali Linux Updates](#slow-kali-linux-updates)
2. [Hardware Clock Wrong in Kali Linux](#hardware-clock-wrong-in-kali-linux)
3. [Setup NTP servers in Kali Linux](#setup-ntp-servers-in-kali-linux)
4. [How to setup .htaccess for a nophp directory](#howto-setup-htaccess-for-a-nophp-directory)
5. [Issues installing VirtualBox additions in Kali Linux](#issues-installing-vbox-additions)
6. [VirtualBox shares not showing up](#virtualbox-shares)
7. [Screenshots in Kali Linux](#screenshots-in-kali-linux)
8. [Can't SSH with root into your machine](#cant-ssh-with-root)
9. [Managing BurpSuite Proxy](#managing-burpsuite-proxy)
10. [File format issues in downloaded exploit source files](#file-format-issues)

<a name="slow-kali-linux-updates"></a>
## Slow Kali Linux Updates
When performing apt-get update in Kali Linux you may get VERY slow download speeds even on high bandwidth connections. You can perform the following change to gain significantly faster download speeds for all of the distribution updates.<br />

Update your repository source list
```
# Edit /etc/apt/sources.list
 
# Change
deb http://http.kali.org/kali kale-rolling main non-free contrib
deb-src http://http.kali.org/kali kale-rolling main non-free contrib
 
# To
deb http://repo.kali.org/kali kale-rolling main non-free contrib
deb-src http://repo.kali.org/kali kale-rolling main non-free contrib
```

<a name="hardware-clock-wrong-in-kali-linux"></a>
## Hardware Clock Wrong in Kali Linux
If you have set the correct timezone in Kali Linux and your time is still wrong even after turning on "Automatic Date & Time" then the hardware clock may be off.<br />

There seem to be two ways to handle this:
* Reboot into the BIOS and make sure the date and time is correct there (do this first)
* Run hwclock and ntpd commands while in the OS

You can see what the Linux machine thinks the time is by executing:
```
root@sengen:~# hwclock --debug
hwclock from util-linux 2.28.1
Using the /dev interface to the clock.
Last drift adjustment done at 1474714382 seconds after 1969
Last calibration done at 1474714382 seconds after 1969
Hardware clock is on UTC time
Assuming hardware clock is kept in UTC time.
Waiting for clock tick...
...got clock tick
Time read from Hardware Clock: 2016/09/24 10:55:25
Hw clock time : 2016/09/24 10:55:25 = 1474714525 seconds since 1969
Time since last adjustment is 143 seconds
Calculated Hardware Clock drift is 0.000000 seconds
2016-09-24 03:55:24.947634-8:00
```

If this output is wrong you can reset your hardware clock via the following:
```
root@sengen:~# ntpd -qg
24 Sep 03:56:43 ntpd[35224]: ntpd 4.2.8p8@1.3265-o Tue Jun  7 20:34:16 UTC 2016 (1): Starting
24 Sep 03:56:43 ntpd[35224]: Command line: ntpd -qg
24 Sep 03:56:43 ntpd[35224]: proto: precision = 0.027 usec (-25)
24 Sep 03:56:43 ntpd[35224]: Listen and drop on 0 v6wildcard [::]:123
24 Sep 03:56:43 ntpd[35224]: Listen and drop on 1 v4wildcard 0.0.0.0:123
24 Sep 03:56:43 ntpd[35224]: Listen normally on 2 lo 127.0.0.1:123
24 Sep 03:56:43 ntpd[35224]: Listen normally on 3 eth0 192.168.52.132:123
24 Sep 03:56:43 ntpd[35224]: Listen normally on 4 lo [::1]:123
24 Sep 03:56:43 ntpd[35224]: Listen normally on 5 eth0 [fe80::20c:29ff:fe1e:c6fb%2]:123
24 Sep 03:56:43 ntpd[35224]: Listening on routing socket on fd #22 for interface updates
24 Sep 03:56:44 ntpd[35224]: Soliciting pool server 173.208.177.234
24 Sep 03:56:45 ntpd[35224]: Soliciting pool server 50.0.191.226
24 Sep 03:56:45 ntpd[35224]: Soliciting pool server 4.53.160.75
24 Sep 03:56:46 ntpd[35224]: Soliciting pool server 204.2.134.163
24 Sep 03:56:46 ntpd[35224]: Soliciting pool server 96.226.123.229
24 Sep 14:32:44 ntpd[35224]: ntpd: time set +38157.952268 s
ntpd: time set +38157.952268s
```

<a name="setup-ntp-servers-in-kali-linux"></a>
## Setup NTP servers in Kali Linux
Kali Linux may not properly sync up it's date and time.  You can setup working NTP servers using the following instructions.<br />

Links
* Forum post: https://www.kalilinux.net/threads/ntp-settings-on-kali.280/
* NTP Server list: http://www.pool.ntp.org/zone/north-america

```
Edit /etc/ntp.conf
 
Replace the following
 
pool 0.debian.pool.ntp.org iburst
pool 1.debian.pool.ntp.org iburst
pool 2.debian.pool.ntp.org iburst
pool 3.debian.pool.ntp.org iburst
 
with
 
server 0.north-america.pool.ntp.org
server 1.north-america.pool.ntp.org
server 2.north-america.pool.ntp.org
server 3.north-america.pool.ntp.org
 
Then restart NTP
/etc/init.d/ntp restart
```

<a name="howto-setup-htaccess-for-a-nophp-directory"></a>
## How to Setup .htaccess for a NoPHP Directory
Some RFI exploits may run against the local system. For example, when compromising a machine, I had pointed the victim to a php exploit on my local system. The exploit was instead running against my local system. This is due to the local Apache web server running the code as a normal web call.<br />

To disable this and to setup a specific directory where php does not execute, the following must be done.
* Create a new directory in /var/www/html called nophp.
* Edit the /etc/apache2/apache2.conf file

Within this file is a section regarding directories. A new directories section must be created for the /var/www/html/nophp directory that sets the php_flag engine off directive.
```
<Directory /var/www/html/nophp>
        Options Indexes FollowSymLinks
        AllowOverride None
        php_flag engine off
        Require all granted
</Directory>
```

<a name="issues-installing-vbox-additions"></a>
## Issues installing Virtual Box Linux Additions in Kali Linux VM
After mounting the Virtual Box Linux Additions ISO
```
# Copy the files to a temp directory in your home directory
mkdir ~/tmp
cp -r * /media/cdrom0 ~/tmp
umount /media/cdrom0
```

Install dkms if it is not installed
```
apt-get install -y dkms
```

Install the Virtual Box Linux Additions
```
chmod +x ~/tmp/VBoxLinuxAdditions.run
~/tmp/VBoxLinuxAdditions.run
```

If you have failures during the install (particularly if you just did an "apt-get dist-upgrade" which is why you're doing this again) it is most likely due to the Linux Kernel being upgraded and you do not have the matching headers.<br />
Check for which kernel version you have installed
```
root@kali:~# uname -a
Linux kali 4.9.0-kali4-686 #1 SMP Debian 4.9.30-2kali1 (2017-06-22) i686 GNU/Linux
```

Check to see what you currently have installed
```
root@kali:~# apt list | grep linux-headers

WARNING: apt does not have a stable CLI interface. Use with caution in scripts.

linux-headers-4.9.0-kali3-686/now 4.9.18-1kali1 i386 [installed,local]
linux-headers-4.9.0-kali3-686-pae/now 4.9.18-1kali1 i386 [installed,local]
linux-headers-4.9.0-kali3-all/now 4.9.18-1kali1 i386 [installed,local]
linux-headers-4.9.0-kali3-all-i386/now 4.9.18-1kali1 i386 [installed,local]
linux-headers-4.9.0-kali3-common/now 4.9.18-1kali1 all [installed,local]
linux-headers-4.9.0-kali3-common-rt/now 4.9.18-1kali1 all [installed,local]
linux-headers-4.9.0-kali3-rt-686-pae/now 4.9.18-1kali1 i386 [installed,local]
linux-headers-4.9.0-kali4-686/kali-rolling,now 4.9.30-2kali1 i386 [installed,automatic]
linux-headers-4.9.0-kali4-686-pae/kali-rolling,now 4.9.30-2kali1 i386 [installed,automatic]
linux-headers-4.9.0-kali4-all/kali-rolling,now 4.9.30-2kali1 i386 [installed]
linux-headers-4.9.0-kali4-all-i386/kali-rolling,now 4.9.30-2kali1 i386 [installed,automatic]
linux-headers-4.9.0-kali4-common/kali-rolling,now 4.9.30-2kali1 all [installed,automatic]
linux-headers-4.9.0-kali4-common-rt/kali-rolling,now 4.9.30-2kali1 all [installed,automatic]
linux-headers-4.9.0-kali4-rt-686-pae/kali-rolling,now 4.9.30-2kali1 i386 [installed,automatic]
linux-headers-586/kali-rolling 4.9+80+kali1 i386
linux-headers-686/kali-rolling 4.9+80+kali1 i386
linux-headers-686-pae/kali-rolling,now 4.9+80+kali1 i386 [installed,automatic]
linux-headers-rt-686-pae/kali-rolling 4.9+80+kali1 i386
```

Check for available headers (if you see ones available that match your kernel version you need to install it and then you can re-run the virtual box additions installation)
```
root@kali:~# apt-get update
Get:1 http://repo.kali.org/kali kali-rolling InRelease [30.5 kB]
Get:2 http://repo.kali.org/kali kali-rolling/main i386 Packages [15.4 MB]
Fetched 15.4 MB in 4s (3,276 kB/s)   
Reading package lists... Done

root@kali:~# apt-cache search linux-headers
aufs-dkms - DKMS files to build and install aufs
linux-headers-4.9.0-kali4-686 - Header files for Linux 4.9.0-kali4-686
linux-headers-4.9.0-kali4-686-pae - Header files for Linux 4.9.0-kali4-686-pae
linux-headers-4.9.0-kali4-all - All header files for Linux 4.9 (meta-package)
linux-headers-4.9.0-kali4-all-i386 - All header files for Linux 4.9 (meta-package)
linux-headers-4.9.0-kali4-common - Common header files for Linux 4.9.0-kali4
linux-headers-4.9.0-kali4-common-rt - Common header files for Linux 4.9.0-kali4-rt
linux-headers-4.9.0-kali4-rt-686-pae - Header files for Linux 4.9.0-kali4-rt-686-pae
linux-headers-586 - Header files for Linux 586 configuration (dummy package)
linux-headers-686 - Header files for Linux 686 configuration (meta-package)
linux-headers-686-pae - Header files for Linux 686-pae configuration (meta-package)
linux-headers-rt-686-pae - Header files for Linux rt-686-pae configuration (meta-package)
linux-libc-dev-alpha-cross - Linux Kernel Headers for development (for cross-compiling)
linux-libc-dev-arm64-cross - Linux Kernel Headers for development (for cross-compiling)
linux-libc-dev-armel-cross - Linux Kernel Headers for development (for cross-compiling)
linux-libc-dev-armhf-cross - Linux Kernel Headers for development (for cross-compiling)
linux-libc-dev-hppa-cross - Linux Kernel Headers for development (for cross-compiling)
linux-libc-dev-m68k-cross - Linux Kernel Headers for development (for cross-compiling)
linux-libc-dev-mips-cross - Linux Kernel Headers for development (for cross-compiling)
linux-libc-dev-mips64-cross - Linux Kernel Headers for development (for cross-compiling)
linux-libc-dev-mips64el-cross - Linux Kernel Headers for development (for cross-compiling)
linux-libc-dev-mipsel-cross - Linux Kernel Headers for development (for cross-compiling)
linux-libc-dev-powerpc-cross - Linux Kernel Headers for development (for cross-compiling)
linux-libc-dev-powerpcspe-cross - Linux Kernel Headers for development (for cross-compiling)
linux-libc-dev-ppc64-cross - Linux Kernel Headers for development (for cross-compiling)
linux-libc-dev-ppc64el-cross - Linux Kernel Headers for development (for cross-compiling)
linux-libc-dev-s390x-cross - Linux Kernel Headers for development (for cross-compiling)
linux-libc-dev-sh4-cross - Linux Kernel Headers for development (for cross-compiling)
linux-libc-dev-sparc64-cross - Linux Kernel Headers for development (for cross-compiling)
linux-headers-4.9.0-kali3-common-rt - Common header files for Linux 4.9.0-kali3-rt
linux-headers-4.9.0-kali3-common - Common header files for Linux 4.9.0-kali3
linux-headers-4.9.0-kali3-all-i386 - All header files for Linux 4.9 (meta-package)
linux-headers-4.9.0-kali3-rt-686-pae - Header files for Linux 4.9.0-kali3-rt-686-pae
linux-headers-4.9.0-kali3-all - All header files for Linux 4.9 (meta-package)
linux-headers-4.9.0-kali3-686-pae - Header files for Linux 4.9.0-kali3-686-pae
linux-headers-4.9.0-kali3-686 - Header files for Linux 4.9.0-kali3-686
```

<a name="virtualbox-shares"></a>
## VirtualBox shares not showing up
### Setting up a new VirtualBox share
1. Click Devices -> Shared Folders -> Shared Folder Settings
2. Click "Add new shared folder"
3. Select a path on the host, give folder name, and check auto-mount and make permanent

### Mounting
At this point, depending on Linux distribution, you may see the shared folder pop up on your desktop in which you would be good to go. In other cases, you will see nothing happen at all.
1. Install "virtualbox-guest-utils" in the guest Linux VM
  * sudo apt-get install virtualbox-guest-utils
2. Manually mount the shared host directory
  * sudo mkdir /mnt/shared
  * sudo mount -t vboxsf Share /mnt/share <i>(where "Share" is the name you gave it when adding it in VirtualBox)</i>

<a name="screenshots-in-kali-linux"></a>
## Screenshots in Kali Linux
KeepNote
* To take a screenshot of a specific section of the screen you can press CTRL-INSERT and then drag a section of the screen you want in the image.  You can then paste this into your document.

Linux
* You can use a Linux tool call "screenshot" which offers similar functionality. Press SHIFT+PRTSCR to capture a specific area of the screen.  The image is dropped into your Pictures directory.

<a name="cant-ssh-with-root"></a>
## Can't SSH with root into your machine
When pivoting through networks you'll end up doing port forwarding and creating reverse SSH tunnels back into your linux machine. By default, in Debian root cannot do this for security reasons.<br /><br />
<i>Change required to allow reverse SSH shells using the root account (only the Kali machine, not on your daily Linux machine)</i>
```
root@sengen:~# vim /etc/ssh/sshd_config
 
Change:
PermitRootLogin prohibit-password
 
To:
PermitRootLogin yes
 
Restart SSH service
root@sengen:~# service ssh restart
```

<a name="managing-burpsuite-proxy"></a>
## Managing BurpSuite proxy
Proxy Management
* To make things easier for switching between using the Burp proxy and not I found that the "Proxy Selector" add-on worked the best
* You can do a search in the add-on's repository for FireFox/Chrome/Safari and find this add-on
* You then can add a BurpSuite proxy setting with 127.0.0.1:8080 as the proxy for when you want to intercept traffic

<a name="file-format-issues"></a>
## File format issues in downloaded exploit source files
From time-to-time you'll grab a file that was created on Windows but you want to use it on Linux (or the other way around) and there are return character issues in it. One thing that may fix your issue is using the dos2unix or unix2dos commands.

```
root@kali:~# dos2unix test.txt 
dos2unix: converting file test.txt to Unix format...
root@kali:~# unix2dos test.txt
unix2dos: converting file test.txt to DOS format...
```

