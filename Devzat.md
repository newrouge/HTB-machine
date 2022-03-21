# Devzat Machine(10.10.11.118)

## Info:


![Screenshot from 2022-03-08 20-54-04](https://user-images.githubusercontent.com/79413473/157268954-af3956c3-83b4-4c08-937c-5b6854156225.png)

## Recon:

Starting with the nmap scan using rustscan, `rustscan -a 10.10.11.118 -u 5000 -- -A`. This will scan for open ports at very high speed and also do nmap scan on them.
```
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    syn-ack Apache httpd 2.4.41
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: devzat - where the devs at
8000/tcp open  ssh     syn-ack (protocol 2.0)
| fingerprint-strings: 
|   FourOhFourRequest, GenericLines, GetRequest, NULL, Socks4, Socks5, X11Probe: 
|_    SSH-2.0-Go
| ssh-hostkey: 
|   3072 6a:ee:db:90:a6:10:30:9f:94:ff:bf:61:95:2a:20:63 (RSA)
|_ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDTPm8Ze7iuUlabZ99t6SWJTw3spK5GP21qE/f7FOT/P+crNvZQKLuSHughKWgZH7Tku7Nmu/WxhZwVUFDpkiDG1mSPeK6uyGpuTmncComFvD3CaldFrZCNxbQ/BbWeyNVpF9szeVTwfdgY5PNoQFQ0reSwtenV6atEA5WfrZzhSZXWuWEn+7HB9C6w1aaqikPQDQSxRArcLZY5cgjNy34ZMk7MLaWciK99/xEYuNEAbR1v0/8ItVv5pyD8QMFD+s2NwHk6eJ3hqks2F5VJeqIZL2gXvBmgvQJ8fBLb0pBN6xa1xkOAPpQkrBL0pEEqKFQsdJaIzDpCBGmEL0E/DfO6Dsyq+dmcFstxwfvNO84OmoD2UArb/PxZPaOowjE47GRHl68cDIi3ULKjKoMg2QD7zrayfc7KXP8qEO0j5Xws0nXMll6VO9Gun6k9yaXkEvrFjfLucqIErd7eLtRvDFwcfw0VdflSdmfEz/NkV8kFpXm7iopTKdcwNcqjNnS1TIs=
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.60%I=7%D=3/8%Time=62277583%P=x86_64-pc-linux-gnu%r(NUL
SF:L,C,"SSH-2\.0-Go\r\n")%r(GenericLines,C,"SSH-2\.0-Go\r\n")%r(GetRequest
SF:,C,"SSH-2\.0-Go\r\n")%r(X11Probe,C,"SSH-2\.0-Go\r\n")%r(FourOhFourReque
SF:st,C,"SSH-2\.0-Go\r\n")%r(Socks5,C,"SSH-2\.0-Go\r\n")%r(Socks4,C,"SSH-2
SF:\.0-Go\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```  
nmap identified two ssh services, on port 22 & 8000. Port 80 is webs server running **Apache 2.4.41**.  Entering ip in browser will redirect to **devzat.htb**.

![Screenshot from 2022-03-08 21-03-11](https://user-images.githubusercontent.com/79413473/157270896-a1cf1939-984c-47c8-834c-545d2cbab639.png)

So let's add that to our */etc/hosts* file i.e **10.10.11.118 devzat.htb**. 

![Screenshot from 2022-03-08 21-08-52](https://user-images.githubusercontent.com/79413473/157271903-6acee7e0-8ea6-4d35-b678-9d1fe0562533.png)

Let's also run vhost fuzzing in background along with other scans, and it finds pets subdomain.

```
ffuf -u http://devzat.htb/ -w ~/wordlist/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.devzat.htb" -fw 18
``` 
![Screenshot from 2022-03-08 21-11-50](https://user-images.githubusercontent.com/79413473/157272283-4475b7a9-9f66-4b67-a81d-635f856a45da.png)

 Let also add that to hosts file **10.10.11.118 devzat.htb pets.devzat.htb**.
 
 ![Screenshot from 2022-03-08 21-12-54](https://user-images.githubusercontent.com/79413473/157272634-872483c8-514b-4751-90fa-b7d4781dcf3d.png)

There is one potential user on contact page of devzat.htb. Other than that web fuzzing doesn't reveal much except *assets*, *images* etc. directory.

![Screenshot from 2022-03-08 21-14-10](https://user-images.githubusercontent.com/79413473/157272813-7da3cf14-cf36-4938-aba4-f647d014f7bd.png)

Fuzzing on **pets.devzat.htb** a **build** directory. Which has a js file on [unminifying](https://beautifier.io/) that js code. we can notice an api endpoint **api/pet** where some post is sent. so fuzzing **/api** can be a potential thing in future.

![Screenshot from 2022-03-08 21-20-51](https://user-images.githubusercontent.com/79413473/157274070-94d668a6-850c-4bbd-83f9-149167387a88.png)

![Screenshot from 2022-03-08 21-22-03](https://user-images.githubusercontent.com/79413473/157274344-28fb0f7b-f836-422c-819b-1201766d7149.png)


## Foothold:

Exploring the functionalities on pets domain. There is option to add pets on this page and GET request is made to **/api/pet** endpoitn tp fetch all pets details. And post request is made to same endpoint to add another pet. While Delete options is not implemented yet.

![Screenshot from 2022-03-08 21-27-50](https://user-images.githubusercontent.com/79413473/157275420-2c4c0d60-6105-448e-ad53-3b555f640113.png)

![Screenshot from 2022-03-08 21-28-06](https://user-images.githubusercontent.com/79413473/157275504-30991925-d4ab-479d-a1ed-f4f20ccd1c8f.png)

As our input is reflected we can think of different injection vulnerabilities. But all attempts failed either pet was not added or exit status 1.

![Screenshot from 2022-03-08 21-38-45](https://user-images.githubusercontent.com/79413473/157284878-c83eeb67-2457-4092-8ea3-166bf2f15b67.png)

As this was going nowhere, let's do little fuzzing which reveals ther is a **.git** directory exposed. But that's not how i found it first time. I have this extension called [DotGit](https://addons.mozilla.org/en-US/firefox/addon/dotgit/?utm_source=addons.mozilla.org&utm_medium=referral&utm_content=search) which sends **.git/HEAD** and **.env** request to every website i visit and if it find something it notifies. I think everyone pentester should have it. Let's look into this .git directory using [GitTools](https://github.com/internetwache/GitTools), i always use this. 

1. ` ./gitdumper.sh http://pets.devzat.htb/.git/ /tmp/devzat` Dumping the git repository in devzat directory on my machine.
2. `./extractor.sh /tmp/devzat/ /tmp/devzat_ext` now this new directory will have all the source code that have been commited in that git repo.

![Screenshot from 2022-03-08 22-33-51](https://user-images.githubusercontent.com/79413473/157288295-1f84cf1f-8b55-4bbd-9182-a3b99673a3dd.png)

Looks like author of this git repo. is same user we saw on contact page i.e *patrick*. Also this application is written in go langauge. Although this was also hinted with header in http response **My genious go pet server**.

Looking into source code, we find something interesting in file **main.go**.

```
func loadCharacter(species string) string {
	cmd := exec.Command("sh", "-c", "cat characteristics/"+species)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		return err.Error()
	}
	return string(stdoutStderr)
}
``` 
To load the characteristics for pets, it passing it in a exec() function with **sh** shell wihtout any filtering. Looks like we have a command injection vulnerability through species parameter. Let's add a pet and modify the request.

![Screenshot from 2022-03-08 22-47-36](https://user-images.githubusercontent.com/79413473/157290712-aef4b2fa-624a-4ec7-b215-e746c785705c.png)

![Screenshot from 2022-03-08 22-48-07](https://user-images.githubusercontent.com/79413473/157290761-0938e9ff-f613-4edc-85eb-1b001da596a3.png)

### Getting user:
 
As command injection is confirmed let's get reverse shell from here, lso looks like **nc** binary is not installed on server. 

![Screenshot from 2022-03-08 22-46-14](https://user-images.githubusercontent.com/79413473/157290863-cc491ec3-7a40-4efd-a9b9-0e71b4ae0be0.png)

I struggled to make any reverse shell work here. But we have other ways to work around as pplication is running under patrick user we can read patrick user's ssh-keys or we can place ours into ssh directory as then we don't have to crack it if it's password proctected.

![Screenshot from 2022-03-08 23-05-46](https://user-images.githubusercontent.com/79413473/157293866-26542988-92cd-4c07-b59e-2777e3810906.png)

![Screenshot from 2022-03-08 23-11-53](https://user-images.githubusercontent.com/79413473/157294805-d73d34b2-793e-4f7b-9e99-59f6dc29044d.png)

*this key needed to be correctly line brak formatted*

Now we can login as patrick user on machine with key. `ssh -i key patrick@devzat.htb`. Don't forget to change key's permission(**-rw-------**) before logging in.

![Screenshot from 2022-03-08 23-13-57](https://user-images.githubusercontent.com/79413473/157295198-34e8c93a-c620-4c44-b666-d15f27ff3c98.png)

## Lateral Movement: Exploting outdated influxdb 

After log-in as patrick user, we can see there is another user **catherine** on machine. Now it's little enumeration time on box.

Let's check apache files. `cat /etc/apache2/sites-enabled/000-default.conf`

![Screenshot from 2022-03-11 21-14-53](https://user-images.githubusercontent.com/79413473/157900357-05b0e2d4-75e0-4b61-921a-dd0a88960f7c.png)

on port listening for **devxat.htb** and vhost **pets.devzat.htb** which is proxeid to port 5000. **ProxyPass / http://127.0.0.1:5000/**.

In patrick's home directory there is another application called devzat which is a chatting application for devs, hence name devzat.

![Screenshot from 2022-03-11 21-17-03](https://user-images.githubusercontent.com/79413473/157900910-283b7a8b-8d6f-4ad9-93f7-5c40cc40e112.png)

![Screenshot from 2022-03-11 21-18-06](https://user-images.githubusercontent.com/79413473/157900968-faf6140b-807f-4851-8679-379f2051a617.png)

Now port 8000 is for this application.  looking around in *devchat.go* file we can notice some mention of influxdb.

![Screenshot from 2022-03-08 23-19-32](https://user-images.githubusercontent.com/79413473/157901562-7186cd99-baf5-45f4-8534-37d4af8530d5.png)

Let's try to connect to this chat system. `nc devzat.htb 8000` from our machine as there is no netcat on machine. It's banner tells SSH-2.0-Go. But nothing useful. As it's ssh let's try to connect with ssh to it. `ssh patrick@devzat.htb -p 8000`.

![Screenshot from 2022-03-11 21-28-26](https://user-images.githubusercontent.com/79413473/157902692-b866cbf2-d08f-4af8-86a2-6032385bd5f1.png)


Also this code tells why it aksing for new username in `devchat.go`
```
if u.id != "12ca17b49af2289436f303e0166030a21e525d266e209267433801a8fd4071a0" {
                for possibleName == "patrick" || possibleName == "admin" || possibleName == "catherine" {
                        u.writeln("", "Nickname reserved for local use, please choose a different one.")
                        u.term.SetPrompt("> ")
                        possibleName, err = u.term.ReadLine()
```

Let's pick a **test** username for this and explore this application.

![Screenshot from 2022-03-11 21-30-52](https://user-images.githubusercontent.com/79413473/157903152-432ca1c7-1292-4118-9fc5-4a3a7c2950db.png)

Running **/help** shows which github application it's exactly running and possible commands to run.

![Screenshot from 2022-03-11 21-33-03](https://user-images.githubusercontent.com/79413473/157903552-54fbbfe7-7382-4956-8068-aacedfb18f24.png)

You can run commands on this with `/command`. 
![Screenshot from 2022-03-11 21-36-16](https://user-images.githubusercontent.com/79413473/157904124-1f24b3ad-c4e1-41cd-8842-c228f2c42ef2.png)

For i didn't find anything interesting here, let's look into influxdb as it was mentioned earlier. Port 8086 is open which is influxdb. As there is no influxdb client installed on machine. we would have to find another way to communicate with it. Turns out we can send http request to influxb. 

`curl 127.0.0.1:8086` gives 404 not found, let's look for header received. `curl -sL -I localhost:8086/ping` ping endpoint gives health of influxdb.

![Screenshot from 2022-03-11 21-51-02](https://user-images.githubusercontent.com/79413473/157906649-de3fde05-470a-4594-8cd4-82a1a3f20e8e.png)

headers reveal influxdb version 1.7.5 which vulnerable to . There is an authentication bypass vulnerability. Let's search for an exploit for it and download this [CVE-2019-20933](https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933). It needs a username which it comes with default one also we can create our own also.

i created a list of usernames i have seen indevchat.go file and /etc/passwd file.
```
catherine
patrick
devzat
admin
``` 
Also as port 8086 is not accessibble from outside, i port forwarded it to my localhost 
```
ssh -i key -L 8086:127.0.0.1:8086 patrick@devzat.htb
``` 
Now let's run the exploit & we get access as admin user.

![Screenshot from 2022-03-11 22-04-05](https://user-images.githubusercontent.com/79413473/157908798-ce6d0244-a7c7-44e8-a8b7-325714117206.png)


Now let's use devzat database and qery for tables and it's records. In influxdb we refer tables as measurements. so instead of show tables we use SHOW measurements. OR maybe i got it wrong but compared to MySql i understood it like this.

![Screenshot from 2022-03-11 22-12-33](https://user-images.githubusercontent.com/79413473/157910094-df794304-35ed-4c67-96d3-b578278ffd8d.png)

Let's see all records from user table.

![Screenshot from 2022-03-11 22-14-16](https://user-images.githubusercontent.com/79413473/157910388-b9291a86-ed7f-453f-baa3-4d6403bee76b.png)

```
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "time",
                        "enabled",
                        "password",
                        "username"
                    ],
                    "name": "user",
                    "values": [
                        [
                            "2021-06-22T20:04:16.313965493Z",
                            false,
                            "WillyWonka2021",
                            "wilhelm"
                        ],
                        [
                            "2021-06-22T20:04:16.320782034Z",
                            true,
                            "woBeeYareedahc7Oogeephies7Aiseci",
                            "catherine"
                        ],
                        [
                            "2021-06-22T20:04:16.996682002Z",
                            true,
                            "RoyalQueenBee$",
                            "charles"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}
```
it reveals catherine's password. Which is actually her password on machine.

![Screenshot from 2022-03-11 22-15-09](https://user-images.githubusercontent.com/79413473/157910524-be859fd5-bdca-4e7f-ab94-4324b93513b9.png)

Now you can read user flag.

![Screenshot from 2022-03-11 22-16-19](https://user-images.githubusercontent.com/79413473/157910698-f3cffe5a-476a-4bb6-9c92-82ea27d17f76.png)

## Privilege Escaltion

Now i remember while enumerating for catherine i saw something interesting in */var/backups* which at the moment was only accessible by catherine user.

![Screenshot from 2022-03-11 22-43-52](https://user-images.githubusercontent.com/79413473/157915035-3a58cd01-0039-47c3-854d-a24efd5b4647.png)

Now there are two version of devchat here backuped, let's copy them somewhere temporarily or transfer to your machine and unzip it. Turns out there is another version of devchat available on this machine. Also looking into listening ports

![Screenshot from 2022-03-11 22-47-55](https://user-images.githubusercontent.com/79413473/157915678-e536c842-8c37-4d62-9d77-0eec67e9ced0.png)

we know that
+ 80 & 5000 is webserver
+ 8086 is inluxdb
+ 22 is ssh
+ what is 8443???

![Screenshot from 2022-03-11 22-50-13](https://user-images.githubusercontent.com/79413473/157915989-99ce6cfe-803b-4d3a-bcf3-429c9c387951.png)

Another version of devchat is running which is only accessiblt from localhost and more functionalities in it.

![Screenshot from 2022-03-11 22-51-13](https://user-images.githubusercontent.com/79413473/157916114-28b5acad-9156-4998-9720-cd2f03c7d1a4.png)

Interesting, let's do port forward again to be able to ssh on this port.
```
+ ssh -i key -L 8443:127.0.0.1:8443 patrick@devzat.htb

+ ssh test@127.0.0.1 -p 8443
```
to access a file it needs some password to verify. Again some source code review time and we find this **fileCommand** function in `commands.go` file, password is hardcoded for verification.

```
func fileCommand(u *user, args []string) {
	if len(args) < 1 {
		u.system("Please provide file to print and the password")
		return
	}

	if len(args) < 2 {
		u.system("You need to provide the correct password to use this function")
		return
	}

	path := args[0]
	pass := args[1]

	// Check my secure password
	if pass != "CeilingCatStillAThingIn2021?" {
		u.system("You did provide the wrong password")
		return
	}

	// Get CWD
	cwd, err := os.Getwd()
	if err != nil {
		u.system(err.Error())
	}
``` 

Apparently it's running as root and in **/root/devzat** directory.

![Screenshot from 2022-03-11 22-57-49](https://user-images.githubusercontent.com/79413473/157917155-8a530fa8-10fb-4733-8de2-0b84d2718ea5.png)

But we can always move back in directories with `../`. so now we can read root flag and root ssh keys by **/../root.txt** & **/../.ssh/id_rsa** respectively.

And that's how we got root on this machine.

`ssh -i root.key root@devzat.htb`

![Screenshot from 2022-03-11 23-01-55](https://user-images.githubusercontent.com/79413473/157918131-fd4321c7-05b9-4326-bce1-35bd62063c95.png)

Thank you for reading :)
