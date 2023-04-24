---
title: "Hacking 'Blunder'"
style: border
color: info
comments: true
description: hackthebox.eu easy box challenge
tags: general
---

Hi, this is 079 and this is my first hacking walkthrough.

**Introduction**

You don't see hackers in your everyday life, but you might have seen hackers in movies.(Probably wearing a hoodie.)
With their laptops, they're able to infiltrate into the largest companies and spy on anyone they want.

You might have thought, 'I want to be like that one day', but never had the chance to learn it or even try.
Today, I'm going to give you a quick overview on how a _realistic_ hacking process functions.

**Phases of hacking**

![Phases](https://www.greycampus.com/ckeditor_assets/pictures/181/content_cehoc3.png)

_Reconnaissance_ is just gaining as much information as possible about the target, such as network, host, and the people involved who might hold potential credentials.

Two major segments of reconnaissance:

* Passive: accessing target website, social media, anyway that does not access the target directly.
* Active: Directly interacting with the target, like using _Scanning_ tools.

_Scanning_ is exactly as it sounds, scanning the target.

* Port scanning: using scanning tools like [Nmap](https://en.wikipedia.org/wiki/Nmap) will reveal open ports, live systems, and services running on the ports.
* Network Mapping: You'll use this when dealing a bigger network, scanning for routers and firewalls are your goals.

_Gaining Access_ is the phase where the attacker breaks into the system and gain user privilege, and maybe even administrative privileges.
There are many ways to penetrate into the system depending on the services and vulnerabilities- I will demonstrate later on.

_Maintaining Access_, there are many things you can do once you're in the system. Depending on your goal, you might want to reconnect into the system tomorrow without going through the process above, this can be achieved using Trojans, Rootkits, or Backdoors.

_Clearing Track_ is where the attacker erases all of its tracks after the attack.(If you don't want to get caught.) Deleting logs, registry values, and uninstalling applications used are examples.

Still, it is hard to grasp how these work with just words. But before we get into it, let's define some words.
You don't have to read this section if you already know these terms.

[CVE](https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures): Common vulnerabilities and Exposures are basically any known vulnerabilities that are associated with certain program or version that we can exploit.

Vulnerability: Basically security hole on the target system that we are trying to exploit.

[VPN](https://en.wikipedia.org/wiki/Virtual_private_network): You probably heard it and maybe used it before, a virtual private network allows you to securely connect to other private networks through the public internet.

[sudo](https://en.wikipedia.org/wiki/Sudo): sudo is a tool in Linux that allows you to run commands as another user.

[rainbow table](https://en.wikipedia.org/wiki/Rainbow_table): Contains already-calculated hashes and passwords that we can reference.

[shell](https://en.wikipedia.org/wiki/Shell_(computing)): Ever saw a black window with white texts on it? A CMD?
![cmd](https://raw.githubusercontent.com/079035/079035.github.io/master/images/blunder/cmd.PNG)
 This program allows you to interact directly with your compuer!

[root](https://en.wikipedia.org/wiki/Superuser): Also known as superuser or administrator, you have the overall control over the system, as a hacker, getting a ``root-shell`` is your ultimate goal for the most of the time.

Now let's get right into it.

Our target is **10.10.10.191** in hackthebox.eu A.K.A. **"Blunder"**, you won't be able to access it right now because you need a hackthebox.eu VPN to access it.

![Blunder](https://raw.githubusercontent.com/079035/079035.github.io/master/images/blunder/blunder.PNG)

```sudo openvpn 079.ovpn```
![VPN](https://raw.githubusercontent.com/079035/079035.github.io/master/images/blunder/vpn.PNG)

Establishing connection with the VPN(my username is 079 in hackthebox.eu)
We can confirm the connection was established by typing ```ifconfig tun0```.
My IP is ```10.10.15.71``` within the network.
![my IP](https://raw.githubusercontent.com/079035/079035.github.io/master/images/blunder/IP.PNG)

Remember _Reconnaissance_? Let's access the website at ```10.10.10.191```.
It looks similar to my own website, __boring__, and nothing interesting yet.

![Website](https://raw.githubusercontent.com/079035/079035.github.io/master/images/blunder/web.PNG)

_Scanning_

I scanned the target using Nmap.
![Nmap](https://raw.githubusercontent.com/079035/079035.github.io/master/images/blunder/nmap.PNG)

It reveals that port 21 for FTP and 80 for HTTP are open.
FTP server is closed though.
![FTP](https://raw.githubusercontent.com/079035/079035.github.io/master/images/blunder/ftp.PNG)

I'm going to brute force the subdirectories of the website using [wFuzz](https://tools.kali.org/web-applications/wfuzz).
![wFuzz](https://raw.githubusercontent.com/079035/079035.github.io/master/images/blunder/wfuzz.PNG)

There are other tools to brute force subdirectories such as gobuster and dirb, but wFuzz is got to be my favorite.

![wFuzz2](https://raw.githubusercontent.com/079035/079035.github.io/master/images/blunder/wfuzz2.PNG)

After some fuzzing, wFuzz gave me some interesting pages: ``install.php, robots.txt, todo.txt, about, admin, etc``.
 Let's access ```todo.txt```.
![todo.txt](https://raw.githubusercontent.com/079035/079035.github.io/master/images/blunder/todo.PNG)

Ah, that's why FTP server was down. Wait, but who's *fergus*? He might be a potential user(target).

Let's access ```/admin```.
![admin](https://raw.githubusercontent.com/079035/079035.github.io/master/images/blunder/admin.PNG)

Going to /admin gives us **BLUDIT** with login interface. This is a CMS, Content Management Systems are there to help webmasters(admin) to manage their own websites.
Username 'admin' and password 'admin' unfortunately didn't work.

After looking up about BLUDIT CMS and CVEs, I came across this [analysis](https://rastating.github.io/bludit-brute-force-mitigation-bypass/.)

It uses [CVE-2019-17240](https://nvd.nist.gov/vuln/detail/CVE-2019-17240) to brute-force passwords using wordlists by rotating fake IPs in the ``X-Forwarded-For`` header.

But which wordlist are we going to use?
Well, this fella seems to REALLY like Stephen King, and writes a lot about computers as well?
We could use CeWL to generate our custom wordlist by extracting from the website.
![CeWL](https://raw.githubusercontent.com/079035/079035.github.io/master/images/blunder/cewl.PNG)

The wordlist is now saved into ```wordlist.txt```.

With our custom wordlist and exploit from [github](https://github.com/noraj/Bludit-auth-BF-bypass), we can abuse this CVE.

Launching the script will brute force the password.
![CVE](https://raw.githubusercontent.com/079035/079035.github.io/master/images/blunder/cve.PNG)

Voila! the password is ```RolandDeschain```
![Password](https://raw.githubusercontent.com/079035/079035.github.io/master/images/blunder/password.PNG)

I could successfully login into BLUDIT using ```fergus:RolandDeschain```.
![BLUDIT](https://raw.githubusercontent.com/079035/079035.github.io/master/images/blunder/loggedin.PNG)

```searchsploit``` might give us some vulnerabilities that might be associated with **BLUDIT** and give us a foothold on the system.

![searchsploit](https://raw.githubusercontent.com/079035/079035.github.io/master/images/blunder/searchsploit.PNG)

To use it, we launch [```Metasploit```]("https://en.wikipedia.org/wiki/Metasploit_Project").
![metasploit](https://raw.githubusercontent.com/079035/079035.github.io/master/images/blunder/metasploit.PNG)

![ready](https://raw.githubusercontent.com/079035/079035.github.io/master/images/blunder/ready.PNG)
I've set the LHOST(listening host, me) as ```10.10.15.71```, RHOST(remote host, target) as ```10.10.10.191```, and set the credentials as ```fergus``` and ```RolandDeschain```.

**Ready, set, go.**
![shell](https://raw.githubusercontent.com/079035/079035.github.io/master/images/blunder/exploit.PNG)
Spawned a bash shell using ```python pty```.
Now, we have _gained an access_, although it is just an ```www-data``` foothold, not a proper user.

After some file enumeration, we file ```user.php``` that contains hashes.
![user.php](https://raw.githubusercontent.com/079035/079035.github.io/master/images/blunder/www-data.PNG)

Looking up at the rainbow table gives us the decoded result of the SHA1 hash: ```Password120```.
![rainbow](https://raw.githubusercontent.com/079035/079035.github.io/master/images/blunder/rainbow.PNG)

I could have used [```John the Ripper```](https://en.wikipedia.org/wiki/John_the_Ripper) or [```Hashcat```](https://en.wikipedia.org/wiki/Hashcat), but for time's sake I recommend consulting rainbow tables first then moving on to password cracking tools.

Got the user access as well as the user flag.
![hugo](https://raw.githubusercontent.com/079035/079035.github.io/master/images/blunder/hugo.PNG)

```sudo -l``` to list user privileges.
![sudo-l](https://raw.githubusercontent.com/079035/079035.github.io/master/images/blunder/sudo-l.PNG)

It says that the user can run ```/bin/bash``` as any user except root.

Using [CVE-2019-14287](https://resources.whitesourcesoftware.com/blog-whitesource/new-vulnerability-in-sudo-cve-2019-14287), we can get a root shell.

![CVE-root](https://raw.githubusercontent.com/079035/079035.github.io/master/images/blunder/root.PNG)

![root-flag](https://raw.githubusercontent.com/079035/079035.github.io/master/images/blunder/root-flag.PNG)

Voila! Nothing fancy here.
Was this something like you thought? Although this was an easy box, I'm sure it gave a good overview of how basic hacking works.

Thank you,

[079](https://www.hackthebox.eu/profile/334976)
