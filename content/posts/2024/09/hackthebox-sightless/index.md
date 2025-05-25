---
title: "HTB-Sightless"
date: 2024-09-10
categories: 
  - "HTB-Machine"
tags: 
  - "hackthebox"
  - "linux"
---

## Box Info

| OS | Linux |
| --- | --- |
| Difficulty | Easy |

## Basic Scan

### Nmap

```
nmap -A -O sightless.htb
```

![](./images/image-94.png)

开放端口：`21`、`22`、`80`

Web服务器：`nginx 1.18.0`

FTP服务器：`ProFTPD`

### Dirsearch

```
dirsearch -u sightless.htb -t 50
```

![](./images/image-95.png)

### Gobuster

```
gobuster dir -u http://sightless.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50
```

![](./images/image-96.png)

## CVE-2022-0944

在网页中发现一个`sqlpad`子域名，似乎可以进行sql操作，但是靶机的3306端口是关闭的

![](./images/image-97.png)

在右上角点击发现SQLpad的相关信息：`6.10.0`

![](./images/image-98.png)

![](./images/image-99.png)

Github：[worm-403/scripts (github.com)](https://github.com/worm-403/scripts)

只需要指定攻击机的IP和端口即可

![](./images/image-101.png)

![](./images/image-100.png)

![](./images/image-102.png)

在root用户下并没有找到东西

![](./images/image-103.png)

在`/etc/shadow`，中发现michael的密码hash

使用`hashcat`爆破

![](./images/image-105.png)

登录michael的账号获得`user.txt`

![](./images/image-107.png)

现在的问题是，反弹获得的shell虽然是root权限，但是一部分指令是无法执行的

## Privilege Escalation

上传`linpeas`，发现bash似乎可以用来提权

![](./images/image-111.png)

相关文章：[Linux提权————利用SUID提权\_bash提权-CSDN博客](https://blog.csdn.net/Fly_hps/article/details/80428173)

这些命令都有root权限

![](./images/image-112.png)

使用bash开启新的shell进程，即可看到权限是root

![](./images/image-113.png)

获取到root.txt

![](./images/image-114.png)

## Summary

总体来说比较简单

涉及到一点Linux提权
