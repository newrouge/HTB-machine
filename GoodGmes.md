# GoodGames machine(10.10.11.130)

![Screenshot from 2022-02-24 14-24-47](https://user-images.githubusercontent.com/79413473/155491314-728eeea6-cfa5-4138-96b9-1e866fd69ee3.png)

This box was an easy box with chance of exploring vulnerabilities like password reuse in organization, Server Side Template Injection and SQL injection to pwn a 
gaming website.

## Recon

Starting with recon, port scan shows only 1 port is open. 
**`rustscan -a $IP -u 5000 -- -A`**
```
PORT   STATE SERVICE  REASON  VERSION
80/tcp open  ssl/http syn-ack Werkzeug/2.0.2 Python/3.9.2
|_http-favicon: Unknown favicon MD5: 61352127DC66484D3736CACCF50E7BEB
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Werkzeug/2.0.2 Python/3.9.2
|_http-title: GoodGames | Community and Store
```  
 In website footer it reveals hostname **GoodGames.HTB** Let's add that to hostname in our /etc/hosts file.
 
 ![Screenshot from 2022-02-24 14-32-47](https://user-images.githubusercontent.com/79413473/155492620-81e5eb94-e1b5-49fc-a83f-83bb8c258dc3.png)

Other enumeration like directory scan and vhost fuzzing doesn't reveal much other than there is login panel, where we can sign-in and sign-up.

## Foothold: 

Clickinng on account icon gives a login panel and option to signup.

![Screenshot from 2022-02-24 14-35-28](https://user-images.githubusercontent.com/79413473/155493086-098912d4-4add-4479-9ec6-a29968bff4e3.png)

And any wrong credential will lead to 500 server error, also email field striclly needs a email.

![Screenshot from 2022-02-24 14-36-04](https://user-images.githubusercontent.com/79413473/155493334-56d4f53f-1e4e-4acd-911b-31c76075565e.png)

Let's check signup page

![Screenshot from 2022-02-24 14-37-51](https://user-images.githubusercontent.com/79413473/155493604-bafd6ed4-ba36-4c9d-8d20-fb87be5f37ba.png)

Here you can signup for a new account, say **test:test** and you can also sign-in from here and the thing is this form doesn't need a valid email in email field.

trying to signup with **admin@goodgames.htb** will tell that account already exists. Let's login with our test account.

![Screenshot from 2022-02-24 14-42-05](https://user-images.githubusercontent.com/79413473/155494281-f98e7d0d-ccc5-44f4-8075-4673fc54a21a.png)

although it's says we can update our profile picture and email, there is no such option here. And password reset also adoesn't work. Otherwise we could have tested
for resetting admin's password but it straight out give 500 error. There isn't much here around to do now. Let's move on and try to login as admin. We haven't 
tested SQLi yet anyway on login.

As login field takes valid email, one way is to capture one valid request and play with it in burp or you can test sqli on other panel.

![Screenshot from 2022-02-24 14-47-24](https://user-images.githubusercontent.com/79413473/155495064-ff9f6f8a-9bc6-4939-9048-25f2dd7a88d0.png)

And it was a sqlinjection and an easy one.

![Screenshot from 2022-02-24 14-47-55](https://user-images.githubusercontent.com/79413473/155495245-8daa91ff-7d46-41d3-99b0-4ac981656708.png)

Also there is a new option on admin portal, *setting icon* , which redirect to another vhost **internal-administration.goodgames.htb** which has another login 
panel.

![Screenshot from 2022-02-24 14-48-19](https://user-images.githubusercontent.com/79413473/155495346-62ac40a1-6594-4cd6-93a9-de802fc3b6ed.png)

![Screenshot from 2022-02-24 14-50-19](https://user-images.githubusercontent.com/79413473/155495543-2dd1c550-2cad-4199-9758-c492d3c55a64.png)

At this point i started searching for vulnerabilites for *flask volt dashboard* and wasted few time, without realizing that we have sqlinjection and we haven't 
explored that yet. We ould:
1. Dump database.
2. Check if we have read and write privilege to read files from system.
3. can we spawn a shell from it using sqlmap by uploading a file.

Let's focus on sqlinjection and explore that:

1. strating with sqlmap `sqlmap -u http://goodgames.htb/login --data "email=admin*&password=admin"`. Telling sqlmap to send post request and field to test i.e. 
   email.
2. And sqlmap detects's injection after few moment. Let's check our privilege on system with **"--privileges"** flag.
  `sqlmap -u http://goodgames.htb/login --data "email=admin*&password=admin" --privileges`. And it detects we are running as usage permission which means we can't 
  read or write from and to system. Let's dump the database.
4. `sqlmap -u http://goodgames.htb/login --data "email=admin*&password=admin" -D main -T user --dump` . dumping **user** table from **main**  database. 
 
 ```
  +------+-----------------------+---------+----------------------------------+
| id   | email                 | name    | password                         |
+------+-----------------------+---------+----------------------------------+
| 1    | admin@goodgames.htb   | admin   | 2b22337f218b2d82dfc3b6f77e7cb8ec |
| 2    | muk****@gmail.com     | blitz   | 81dc9bdb52d04dc20036dbd8313ed055 |
| 3    | test@gmail.com        | test    | cc03e747a6afbbcbf8be7668acfebee5 |
| 4    | test@goodgames.htb    | test    | 098f6bcd4621d373cade4e832627b4f6 |
| 5    | test1@gmail.com       | {{7*7}} | 098f6bcd4621d373cade4e832627b4f6 |
+------+-----------------------+---------+----------------------------------+
```  
We can see all the account's created on system and their password hashes. *don't put your real email address and password in ctfs*.
Let's try to crack admin's hash and we can do that easily by googling it or simply putting it in https://crackstation.net/ . And password is **superadministrator**.

Let's try to login with this password on second vhost panel. And we are amdin.

![Screenshot from 2022-02-24 15-05-49](https://user-images.githubusercontent.com/79413473/155498098-658539ce-a6ce-4f12-832d-42468c490939.png)

Now from setting option you can edit your name and other stuff. Let's do that and as it is a python application don't forget to test for SSTI. **{{7*7}}

![Screenshot from 2022-02-24 15-06-52](https://user-images.githubusercontent.com/79413473/155498636-2558d534-b511-4983-a2c9-b8d21b6c720e.png)

![Screenshot from 2022-02-24 15-05-49](https://user-images.githubusercontent.com/79413473/155498650-9491aebb-d397-42a7-89eb-32a16ffa7942.png)











