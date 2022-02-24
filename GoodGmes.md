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

![Screenshot from 2022-02-24 15-09-50](https://user-images.githubusercontent.com/79413473/155498811-6cc208ba-8194-4a5d-b789-c6c17b1c3830.png)

indeed it's reflected as 49. Also it's running jinja template. Now we can get a shell from here using SSTI [payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2). 
Now 0xdf have done a fantastic video on how these payloads actually work you can find it [here](https://www.youtube.com/watch?v=7o1J8vHdlYc).
Also if you want written version of it i have also explained this in this htb machine [blog](https://newrouge.blogspot.com/2022/02/epsilon-hackthebox.html).

I will be using `{{ namespace.__init__.__globals__.os.popen('id').read() }}` this paylaod to get shell. Basically what happens is that you access naespace clas in jinja and in that you access **__init__** function, in python every class has this fucntion defined it's like constructor of that class, after that you access 
**globals** function accessible by init and then you finally can access python modules like **popen** or **os** to run commands.

![Screenshot from 2022-02-24 15-17-41](https://user-images.githubusercontent.com/79413473/155500805-0de50244-44f6-4fd9-b921-4bbbf427cbfc.png)

Let's get a reverse shell from here. One thing although we are entering dob and phone number to update but in request only name is getting processed. Let's look into that request.

![Screenshot from 2022-02-24 15-27-07](https://user-images.githubusercontent.com/79413473/155501665-f94add01-5087-49f9-963a-8faa9f8fae17.png)

only name field is being sent, so anyway other field are just to annoy us :) Let's modify the request and look if anything changes. 

![Screenshot from 2022-02-24 15-29-29](https://user-images.githubusercontent.com/79413473/155502154-17c8566a-3c7f-455f-98c2-dde41909279e.png)


But nothing changes. Let's move on.

## Privilege Escaltion: Docker escape

After getting rev. shell we are already runnning as root.

![Screenshot from 2022-02-24 15-33-27](https://user-images.githubusercontent.com/79413473/155502821-7defbcd9-f4b1-4b1f-bae1-edcb1a8f4722.png)

but ofcourse we are in docker, loking at hostname and dockerfile all over the place. Also one way to confirm if you are running in dockerenv to check
**/proc/1/cgroup**. cgroup is control groups which in combination with namespaces isolate different processes for container environments. They both are linux kernel feature. Namespace allocate resources(CPU,ram etc.) to different processes to give user a VM like feel, and cgroups control that allocation how much resource shoudl be accessible to which process. More on it [here](https://www.nginx.com/blog/what-are-namespaces-cgroups-how-do-they-work/).

So coming back to topic. If you will cat **/proc/1/cgroup** and you see some docker ids means you are in docker and these are control groups are being used by docker. Else these will be balnk. in our case:

![Screenshot from 2022-02-24 15-46-13](https://user-images.githubusercontent.com/79413473/155504982-163db025-7101-4afc-b1f5-48330e943f4b.png)

Let's try to escape this docker.

There is a home directory for user**augustus**. But /etc/passwd has no such user and you can't change user as augustus. Looks like it's mounted from the host machine. You can also run **moount** command to see that indeed it's mounted from host machine and read write permission.

![Screenshot from 2022-02-24 15-51-31](https://user-images.githubusercontent.com/79413473/155505755-5b86d046-1210-4cb0-92e6-84f7f0db501c.png)

Let's enumerate a little bit, looking for processes running and something vulnerable script etc. nothing, but one thing stand out. Running ifconfig gives docker ip. 

![Screenshot from 2022-02-24 15-52-44](https://user-images.githubusercontent.com/79413473/155505934-1f91ad1f-1b34-4e4d-8d46-5c395cb55da3.png)

Now our instance has ip 172.19.0.2, which can mean that there is a 172.19.0.1 which is the first ip in network assigned to host machine generally. Let's checck that. Or you could have enumerated running a for loop for a range.

![Screenshot from 2022-02-24 15-55-14](https://user-images.githubusercontent.com/79413473/155506391-f53317e0-096d-4ff8-84a0-cc096890fbee.png)

172.19.0.1 is listening unlike others. We need to scan for port it listening for. But this box neither **nc* nor **nmap**. But we can use some bash trick using **/dev/tcp** or **/dev/udp** to check if particular port is open. We will send data using tcp or udp protocol on differetn ports and if data is received means it's open.

```
for port in $(seq 1 1000); do (echo "blah" > /dev/tcp/172.19.0.1/$port && echo "open - $port") 2>/dev/null; done

```

It will echo blah on evry port from 1 to 1000 using /dev/tcp and if it succeeds it will say it's open.

![Screenshot from 2022-02-24 16-04-08](https://user-images.githubusercontent.com/79413473/155507870-7de5aca7-ba0a-486c-b82b-7eda19d1a822.png)

Port 22 is open and 80 is open. Port 80 is website we saw on goodgames.htb but 22 was not open when we scanned 10.10.11.130. Let's try ssh as augustus user.
with our cracked password.

![Screenshot from 2022-02-24 16-08-07](https://user-images.githubusercontent.com/79413473/155508529-9e27963a-992f-4375-8abb-eb1b8aad4d40.png)

Now this is same directory as we had on docker machine, just here we are as augustus user and in docker as root. What we create in this directory either way is accessible other way. Outside/inside of docker.

Now there are multiple way's to get root from here. 
1. copy /bin/bash as augustus on host machine into home directory then in docker change it's user to root with suid binary. Then as augustus o host run it as root.
2. Or in docker copy /bin/sh which will automatically be owned by root, as you are root in docker, set suid binary. Now on host run is you will be root.
3. but you can't copy /bin/bash in docker and run it on host, as for bash different shared libraries are used. 

Let's do that 

![Screenshot from 2022-02-24 16-20-34](https://user-images.githubusercontent.com/79413473/155510488-68beb0cd-4d84-4135-8573-ec66f6306d01.png)

![Screenshot from 2022-02-24 16-20-01](https://user-images.githubusercontent.com/79413473/155510491-beeebcc3-8495-4246-b070-a79d90f4196b.png)

and we are root on box.

Thank you
