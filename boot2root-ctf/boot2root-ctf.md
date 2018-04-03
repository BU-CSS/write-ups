# BUCSS Boot2Root CTF 2018 Write Up
This write up details the solutions for the boot2root style CTF run by the Bournemouth University Cyber Security Society. There were no challenges directly specified for this CTF and the flags were not numbered in any particular order, this write up follows the order in which flags were found rather than placed.

***NOTE:*** While I created all of the challenges for this CTF I have approached this write up as if I were tackling the challenges for the first time, this way I have conducted the usual steps I would normally take when solving challenges whose solution I don't already know.

## FTP
I started off with an nmap scan of the target which showed several running services with open ports, one of them being FTP whose banner stated that the user ```ftp_user``` was able to login to the service, without knowing the password however I decided to run hyda against it with the rockyou wordlist, after a few minutes it found the correct password for ```ftp_user```.

```terminal
hydra -l ftp_user -P /usr/share/wordlists/rockyou.txt ftp://payfriends.local
```

After logging in I downloaded the ```easy.txt``` file which contained over 300MB of base64 encoded text, after a few decodes I realised that the contents of the file had been repeatedly encoded with base64, it was easy to recover the original contents with a Python script.

```python
import base64

data = None

with open('easy.txt', 'r') as f:
	data = f.read()

while 'flag' not in data:
	data = base64.b64decode(data.encode()).decode()

print(data)
```

## Maths Test
Next I connected to the service running on port 20000 which turned out to be a set of maths questions that had to be answered quickly (within a second for each question). Another Python script quickly solved this and got me the next flag.

```python
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = 'payfriends.local'
port = 20000
sock.connect((host, port))
started = False

while True:
	data = sock.recv(1024).decode()
	print(data)

	if started is False and 'GO!' in data:
		started = True
	elif started is True:
		answer = str(eval(data.replace(' = ', '')))
		sock.sendall(answer.encode())
		response = sock.recv(1024).decode()

		if 'flag' in response:
			print(response)
			exit()
		elif 'rip' in response:
			exit()
```

## Hidden Page
The first flag I found quickly, after navigating to the target website I immediately examined the source code and found a link to an unfinished section of the site.

![Commented Link](images/site/source-comment.PNG)

Navigating the ```/community``` there was nothing displayed on the page but examining the page source once again revealed the flag.

![Community Flag](images/site/community-flag.PNG)

## Cookie
Next up I decided to examine the page headers, while there was a ```FLAG``` header set, it didn't contain a flag rather just the message ```You don't really think I'm going to keep hiding flags in all the same places do you?```. There was however a cookie containing the value ```WG1lbiBPUiBhdmVuZ2Vycz8KCikjLigQNDoBKXoWFyEKfScoFjoVeRw+ISoqLgp4Ciwseig7eCk3Mm9nCSMuKG9+e2Y=``` which, when decoded from base64 reads the following.

```
Xmen OR avengers?

)#.(4:)z!
}'(:y>!**.
x
,,z(;x)72og	#.(o~{f
```

The capitalised letters spell XOR, making it fairly obvious that what follows is XOR encrypted, probably with a single character key. After copying the XOR encrypted part of the string into a file, a quick Python script easily revealed the flag.

```python
import string

chars = list(string.ascii_lowercase) + list(string.ascii_uppercase)

with open('ciphertext', 'r') as f:
	ct = f.read().strip()

for char in chars:
	print(''.join(chr(ord(char) ^ ord(c)) for c in ct))
```

Looking through the list of outputs and I find the flag.

## Image Flag
For the next flag I decided to examine the image on the site's homepage. Saving a copy locally and running ```steghide info people.jpg``` showed that there was another image file hidden within it. After running ```steghide extract -sf people.jpg``` extracted it which then gave me the next flag.


## News XSS Flag
Time to see what else the site has to offer so it's off the the news page which links to a couple of news articles, interestingly they contain a comments section which I decided to test for cross site scripting vulnerabilities (XSS) and was rewarded with a flag after triggering a stored XSS vulnerability.

```html
<script>alert('xss');</script>
```

## Insecure Direct Object Reference
At this point I decided to check for the ```robots.txt``` file which turned up two interesting paths ```/manage``` and ```/backups```. I decided to start with the backups directory which turned up the ```users.sql``` file in which I found the login details for the user ```d_murphy```. Logging into the account got me nothing except a list of recent transactions, however I noticed that the URL contained the ```acc``` GET parameter which when changed to ```8496384``` displayed the transactions for the account belonging to ```d_pardella``` along with another flag.

![Invalid Account Access](images/site/object-reference-flag.PNG)

## Admin Account Access
Next I moved on to look at ```/manage``` where I found another login form, but this time there was a forgotten password link, a little poking around that page and I found an interesting looking hidden field named ```show_new_password```.

![Hidden Field](images/site/admin-hidden-field.PNG)

Changing the fields value from ```0``` to ```1``` and submitting the form with the username ```admin``` gave me the newly generated password for the admin account. Logging into this account gave me the next flag.

## Broken QR Code
While looking around some of the content directories I came across a file named ```broken.png``` in the ```/static/images``` directory, it contained a QR code but something wasn't right about it, the corner squares didn't contain the black squares they should have instead they were just white.

![Broken QR](images/site/broken.png)

I downloaded the file and used GIMP to add the missing squares into their correct locations, scanning the modified image gave me another flag.

![Fixed QR](images/site/fixed.png)

## WordPress Admin Login
I moved on to look at the linked WordPress blog, examination of the page source or running ```wpscan``` against the site shows that it is running an outdated version of the UserPro plugin which has an authentication bypass vulnerability.

![wpscan results](images/site/blog-vulnerable-plugin.PNG)

Checking Exploit DB reveals that adding ``` ?up_auto_log=true ``` to the URL leads to the user being logged in to the administrator account without the need for any authentication details.

![Admin Logged In](images/site/blog-logged-in.PNG)

A flag was then found on the admin dashboard.

## Mr Robot
Next I went to take a look at the help subdomain and took a look at the robots.txt which rewarded me with a flag.

## Default Credentials
Without much else going on with this site I decided to run ```dirb``` against it which revealed that there was a file named ```todo```, navigating to this file informed me that the site was built using WonderCMS.

![dirb output](images/site/help-dirb.PNG)

A quick look at the WonderCMS project and I found that ```admin``` is the default login to manage the site so I followed the link in the bottom right corner of the site, entered ```admin``` and was logged in revealing another flag.

## PHP Remote Shell
After a quick look around I found that admins were able to upload files without any file type restrictions so I generated a quick weevely shell and uploaded it to the help site. After a bit of exploration I found that the home directory for the user ```pf-docs-user``` was readable by anyone while the others were locked down. The directory contained only one file which contained a password, presumably for ```pf-docs-user``` which allows me to login to the user account over SSH, moving me from the ```www-data``` account to the ```pf-docs-user``` account which also reveals another flag.

## Changing Account
Now logged in as ```pf-docs-user``` I took a look at the groups the user is a member of and re-examined the home directory permissions which showed me that I was able to read the home directory for ```cspruill``` which let me read the file ```remember.txt```. The file contained some ciphertext and a hint that the cipher used was "at my fingertips" pointing me  towards the keyboard cipher, once decoded I get another flag and the password for the ```sysadmin``` account.

## Gaining Privileges
In the home directory for ```sysadmin``` I found a ```flag.txt``` file which was only accessible to the ```netadmin``` account along with an executable called ```emergency_admin_tool``` which had a sticky bit, meaning that it would execute as the user who owns it, in this case ```netadmin```. Launching the executable reveals some sort of lightweight shell environment, to test this I ran ```whoami``` which revealed that I was indeed now running commands as ```netadmin```, so to make life easier I ran ```bash``` to get a proper shell and then read the ```flag.txt``` file to get another flag.

## Moving On
With that done I moved on to perform some basic recon tasks and eventually found that ```netadmin``` had a custom binary path which appeared to contain all the standard Linux binaries but it also had permission to run ```/home/netadmin/bin/passwd localadmin``` as sudo giving me the ability to change that account's password.

## Local Admin
I logged into the server again as ```localadmin``` using SSH and retrieved another flag from the ```flag.txt``` file in the home directory. There was another file which revealed there was a service running on port 60000 which had the ability to provide the password for the root account, the source code for this service was also stored in the home directory but it was obfuscated making it difficult to follow what it actually did.

```python
from binascii import hexlify as Hide

hIde = False
hIDe = input
HIDe = print

root_password = '<hidden>'

def HIDE(HIde):
	return HIde.encode()

def hiDE(hidE):
	hiDe = []

	for hide in range(len(hidE)):
		hIdE = len(hidE) - (hide + 1)
		hiDe.append(hidE[hIdE])

	return hiDe

def HidE(hidE):
	hiDE = int(hidE) + 1
	hiDE = hiDE * 7

	return hiDE

hide = hIDe('Enter the correct password: ')

if hide.isdigit() is hIde:
	HIDe('That\'s not a number')
	exit()

HiDe = Hide(HIDE(str(int(((((((((14992 - 1230) * 2) / 4) - 10394) * -5) / 3) - 146) + -3495) - 877))))
HIde = ''.join(hiDE(hide))
hIDE = str(HidE(''.join(hiDE(HIde))))

if Hide(HIDE(hIDE)) == HiDe:
	HIDe(root_password)
else:
	HIDe('nope')
```

Re-written the code looked like this.

```python
from binascii import hexlify

root_password = '<hidden>'

def string_encode(string):
	return string.encode()

def reverse(password):
	new = []

	for i in range(len(password)):
		index = len(password) - (i + 1)
		new.append(password[index])

	return new

def increment(password):
	new = int(password) + 1
	new = new * 7

	return new

user_input = input('Enter the correct password: ')

if user_input.isdigit() is False:
	print('That\'s not a number')
	exit()

password = hexlify(string_encode(str(int(((((((((14992 - 1230) * 2) / 4) - 10394) * -5) / 3) - 146) + -3495) - 877))))
reversed = ''.join(reverse(user_input))
parsed = str(increment(''.join(reverse(reversed))))

if hexlify(string_encode(parsed)) == password:
	print(root_password)
else:
	print('nope')
```

The script takes an input that must be a number, it then reverses it, reverses it again (so now it's back to its original form) and then changes increments it by 1 and multiplies it by 7. I started by running the calculation in the script in order to get the target value, which turned out to be ```1337```.

```python
int(((((((((14992 - 1230) * 2) / 4) - 10394) * -5) / 3) - 146) + -3495) - 877)
```

Now all I had to do was find the number that would equal 1337 after going through the script's manipulations which is as simple as ```i = (1337 / 7) - 1 ``` which gives ```190```. I connected to port 60000, entered 190 and was rewarded with the following output and another flag.

```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAvQwV/OEGR7GJZ/fmD3ViEMjeyUlPrXyUZ5GkyM9bwixSn0Bf
9zvJyykN+u1ZfiLkeKOeYu9ghRFwmBpSJggCMKHJ7/XFhbjeTj0+mtA6ozgqwbBv
B5GNbJnJxogNOz6qq3ajQIYMlrFRFxinbGixgTfjrsicGOL5WludSeoBhtc7c54V
XPxY+TINugoboyHu0u8Sqvsc8n7rL2yRVlFGQn4ICyWCIFILj93nvS50NV+0LENA
hnHuv3EFYP3iJNiwHauNGO3sYFM1Q5sg/jU9McBiwU/AAAhLuxhjOiNnqA6AQH/x
yvq5j27k9Y4BGvbVz2QIVZvFBaUkWtTq42pg2wIDAQABAoIBAB1b/SYyxEjqF47f
/wizkDFPINpd2lP1Hw8enVraaUO0ong9BSpeTK6Sh6tKpTVjsdvSfUycJH9GABh/
LfbeE4j992Ce6Lglx9Cazlg4soKavHksL3Ibdr1A/QcqJfPnfZX3bM8egmH8070k
hQvfDoIk7eU9HpD23wbbZ4gNIYORMROT4CG0QqvjXq8WCdkZCiYekIriAW8wlS/H
Kw2+kYZgW7pyb93AKWpHHmDXgZvxVL/BHR3rXN7RxRhjAdmR9UsqmOF4ZUuV3rJZ
1ak4x5SGtPJxPNRaTBcvNvm7pe63eiTCrzHBIXgk4TjJxDMdsPY+AWHdVu25mujL
pnKr4ZECgYEA7O8Cz9N2OjYdHIMVwV7bURqq3dYSdACOufhSUvK4P6wdhC12vaCJ
Aml2+hTq+2INkT2uq2j/OFSK02Z5ohyYJE2CfuApxvQd2z5KLbEUsNYrNLzVP3kI
9JRubq8398kfb/+idkoZtQccbVEkpSkGvK0jPjJ04PpK5g9/8+gVic0CgYEAzEKV
Pg1po2lWX8XNJE/F9Lex9E4HSZZ77cxMBjnnnq9H3PxDgqVP0pvZjlTCyBGsxJVk
0k9Jscjz4VYeYJ112ObZuVsxVpIb1xKIb6CsBc96LfAzfYT09284ds7Dzi7INOtg
egiXsXKU74bB3tC9VsIygzYMXD7Z2Z/uHGZ4zUcCgYARobO23YilylMeRQ8AZduy
TGa8vWqAIW59nmIZ9CAL9PX5WRzF/cVUXZ7R+26FKIXT8iAmd1jOy1PNaYnRq4kS
4oW8hVf2i0IRh7AjeFMO2dE7SnYgFBS7hrQ1Hmru0JO7VO21GcyR8SaHaAtvEv+C
WOwPe9fAyj96oVqnPvUjXQKBgQCGpSl+ExdcyfZPAbO9yPxD2cdrtPfm0VT2J2LC
A++j0gV8LapO96wLuAKMaWFQwx3xJE2muO9qS35APyWdKI7joSFKp0t5tqy1dJkN
hIuA9QikOZ+nkTpt1RoSby/xvTLqd3JMX1eneFGnJ1yrBUyaYT8s8Tbqo9+1LlCm
1gGxxwKBgQCPsniEMMLNCkutfe4T18HqxbMoXkKo7JzxBbVHefxbslqyxKqXi237
e8Ek3Vfx6ifRZYdE8pJqvA8Qq6RtrINpsupfa2rvoRTyNuF6gw7UNOqnkBK9z1v9
GNxQTXd/xO2RYhN/sR+Thx5UVnxmm0q+1vBoBeGSZBV61ZH1oRN9qQ==
-----END RSA PRIVATE KEY-----
```

## Rooted
Now that I had the SSH key for the root user I saved it to a file locally and used it to login as root via SSH. I read the ```flag.txt``` file in order to retrieve the next flag and then set to work on the executable called ```bonus_flag```.

Running the file doesn't really do much, resulting in the following output.

```
Are you 1337 enough to get the bonus flag?
I guess not!
```

I fired up GDB in order to examine the executable further and listed the functions it contained.

```terminal
gdb ./bonus_flag
info functions
```

The executable contains a function called ```get_flag```, I decided to start simple by setting a breakpoint on the ```main``` function and then jumping into the ```get_flag``` function which revealed the flag.

```terminal
break main
jump get_flag
```

## Another Root
I remembered that a couple of the examined websites were running on a database, WordPress requires a database and based on the SQL file found earlier, the main site also runs on a MySQL database so I decided to try and login to MySQL using some default credentials ```root:toor``` and sure enough I got access.

```sql
show databases;
use SECRET;
show tables;
SELECT * FROM private_data;
```

![Database Flag](images/system/database-flag.PNG)

## One Last Check
At this point I'd found all but one of the flags so I decided to take another look around the system and stumbled across the flag I was looking for in ```/opt/challenge/you_checked```.
