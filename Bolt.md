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
            if user:
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

