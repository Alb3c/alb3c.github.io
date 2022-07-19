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
> -sC Default Scripts
> -sV Enumerate version
> -oA Output to file
> -v Verbose

```
sudo nmap -sC -sV -oA nmap.output -v
```

## VHost/DNS Discovery

Discover hidden subdomains based on the top 1 Million DNS names: https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt

```
gobuster vhost -u URL -w subdomains-top1million-110000.txt -t 100 -k
gobuster dns -d streamio.htb -w subdomains-top1million-110000.txt -t 100
```

## Web Directory Enumeration

### Wordlist
Dirbuster wordlists:
> /usr/share/dirbuster/wordlists/
IIS directory
> https://raw.githubusercontent.com/digination/dirbuster-ng/master/wordlists/vulns/iis.txt

### Tools

**feroxbuster**

```
feroxbuster -u IP -x EXTENSION -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 100
```

**Dirbuster**

**gobuster**

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

Enumerate Hostname using **nmblookup**

Options
> -A look up by IP address
```
nmblookup -A IP_ADDR
```

Enumerate whatever we can on the box using crackmapexec
```
crackmapexec smb HOST_IP
```
Enumerate the shares
```
crackmapexec smb HOST_IP --shares (Remember to user black username and password using -u "" -p "")
```
Enumerate using smbmap
```
smbmap -H HOST_IP -u "" -p ""
```
