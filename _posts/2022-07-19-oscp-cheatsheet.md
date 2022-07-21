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
Enumerate the shares
```
crackmapexec smb HOST_IP --shares (Remember to user black username and password using -u "" -p "")
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

# Initial Access

## SSH Bruteforce

```
hydra -l USERNAME -p PASSWORD_LIST IP -t 4 ssh
```

# Priv Escalation

## Linux

### Checklist

- [ ] Password reuse (mysql, .bash_history, 000- default.conf...)
- [ ] Checking sudo permissions (sudo -l)
- [ ] Check binary with SUID set ([https://gtfobins.github.io/](https://gtfobins.github.io/#+suid))

