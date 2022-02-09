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
+ Running ffuf we get */admin* which redirect to login panel.
