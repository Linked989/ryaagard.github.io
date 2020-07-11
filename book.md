## Book
![Image](https://www.hackthebox.eu/storage/avatars/dac79630729cd2c675e86bcd809caf5e.png)


- OS: _Linux_
- Difficulty: _Medium_
- Creator: [_MrR3boot_](https://www.hackthebox.eu/home/users/profile/13531)
- User blood: [_xct_](https://www.hackthebox.eu/home/users/profile/13569)
- Root blood: [_xct_](https://www.hackthebox.eu/home/users/profile/13569)



Book was a medium linux box on HackTheBox that first involved getting the administrator user with sql truncation attack, then on the user page we can do some xss magic with pdf-s and on the administrator page we can see the output of that xss, so with that we got LFI(Local File Inclusion) and could read id_rsa file of the user. With the user we can see some logrotate commands running around with pspy and we used logrotten exploit to get root.

# Nmap

So the first thing we do is start the nmap scan to see what open ports are there, I usually do
```
nmap -sC -sV -v -oA nmap/book 10.10.10.176
```
So the parameters are -sC is set to run NSE nmap default scripts, then -sV is to enumerate the versions of the services running on the open ports it finds, then -v is to verbose so we can see the open ports while nmap is running and -oA to output all formats into nmap/ and name them book and then the IP address of the box.
Running that command we can see that ports 21 (SSH) and 80 (The webpage) are open, so first thing we can do I check out the webpage. 
