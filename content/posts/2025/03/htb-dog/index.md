---
title: "HTB-Dog"
date: 2025-03-09
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

## Nmap

```
[root@kali] /home/kali/Dog  
❯ nmap dog.htb -sV -A -Pn -T4        

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
|_  256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-git: 
|   10.10.11.58:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
|_/user/password /user/login /user/logout /?q=admin /?q=comment/reply
|_http-title: Home | Dog
```

可以发现**nmap**直接扫描到了**/.git**目录

## GitDump

```
[root@kali] /home/kali/Dog  
❯ git-dumper http://dog.htb/.git/  ./dog-git    
```

由于存在一个登录页面，我们需要寻找到存在的用户：**tiffany**

```
[root@kali] /home/kali/Dog/dog-git (master) 
❯ grep -r "@dog.htb"
files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json:        "tiffany@dog.htb"
```

查看**settings.php**中，得到**mysql**数据库的密码

```
[root@kali] /home/kali/Dog/dog-git (master) 
❯ head settings.php -n 20
<?php
/**
 * @file
 * Main Backdrop CMS configuration file.
 */

/**
 * Database configuration:
 *
 * Most sites can configure their database by entering the connection string
 * below. If using primary/replica databases or multiple connections, see the
 * advanced database documentation at
 * https://api.backdropcms.org/database-configuration
 */
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
$database_prefix = '';

/**
 * Site configuration files location.
 *
```

登录**tiffany**的用户来到后台

```
tiffany:BackDropJ2024DS2024
```

![](./images/image-142.png)

## Own www-data

发现一个可以上传文件的页面

![](./images/image-143.png)

进入到**Manual installation**

这里只允许上传**tar tgz gz bz2**格式

这里我是从官网上下载了一个模块

- [Modules for Backdrop CMS | Backdrop CMS](https://backdropcms.org/modules)

![](./images/image-145.png)

解压后修改这个地方

![](./images/image-148.png)

然后重新打包成一个**tar.gz**

```
tar -czvf bean.tar.gz *
```

上传成功

![](./images/image-147.png)

**Enable**之后访问这个路径即可执行命令，得到**www-data**的**shell**

![](./images/image-149.png)

![](./images/image-150.png)

## Own johncusack

进入**mysql**

![](./images/image-151.png)

发现存在有**jobert**的密码**hash**，但是并不能爆破。

![](./images/image-152.png)

尝试使用数据库的密码来登录**johncusack**成功

```
[root@kali] /home/kali  
❯ ssh johncusack@dog.htb     #BackDropJ2024DS2024
```

## Root

查看特殊命令

```
-bash-5.0$ sudo -l
[sudo] password for johncusack: 
Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
```

查看具体内容

```
<?php
/**
 * @file
 * A command line utility for Backdrop CMS.
 */

// Exit gracefully with a meaningful message if installed within a web
// accessible location and accessed in the browser.
if (!bee_is_cli()) {
  echo bee_browser_load_html();
  die();
}

// Set custom error handler.
set_error_handler('bee_error_handler');

// Include files.
require_once __DIR__ . '/includes/miscellaneous.inc';
require_once __DIR__ . '/includes/command.inc';
require_once __DIR__ . '/includes/render.inc';
require_once __DIR__ . '/includes/filesystem.inc';
require_once __DIR__ . '/includes/input.inc';
require_once __DIR__ . '/includes/globals.inc';

// Main execution code.
bee_initialize_server();
bee_parse_input();
bee_initialize_console();
bee_process_command();
bee_print_messages();
bee_display_output();
exit();

/**
 * Custom error handler for `bee`.
 *
 * @param int $error_level
 *   The level of the error.
 * @param string $message
 *   Error message to output to the user.
 * @param string $filename
 *   The file that the error came from.
 * @param int $line
 *   The line number the error came from.
 * @param array $context
 *   An array of all variables from where the error was triggered.
 *
 * @see https://www.php.net/manual/en/function.set-error-handler.php
 * @see _backdrop_error_handler()
 */
function bee_error_handler($error_level, $message, $filename, $line, array $context = NULL) {
  require_once __DIR__ . '/includes/errors.inc';
  _bee_error_handler_real($error_level, $message, $filename, $line, $context);
}

/**
 * Detects whether the current script is running in a command-line environment.
 */
function bee_is_cli() {
  return (empty($_SERVER['SERVER_SOFTWARE']) && (php_sapi_name() == 'cli' || (is_numeric($_SERVER['argc']) && $_SERVER['argc'] > 0)));
}

/**
 * Return the HTML to display if this page is loaded in the browser.
 *
 * @return string
 *   The concatentated html to display.
 */
function bee_browser_load_html() {
  // Set the title to use in h1 and title elements.
  $title = "Bee Gone!";
  // Place a white block over "#!/usr/bin/env php" as this is output before
  // anything else.
  $browser_output = "<div style='background-color:white;position:absolute;width:15rem;height:3rem;top:0;left:0;z-index:9;'>&nbsp;</div>";
  // Add the bee logo and style appropriately.
  $browser_output .= "<img src='./images/bee.png' align='right' width='150' height='157' style='max-width:100%;margin-top:3rem;'>";
  // Add meaningful text.
  $browser_output .= "<h1 style='font-family:Tahoma;'>$title</h1>";
  $browser_output .= "<p style='font-family:Verdana;'>Bee is a command line tool only and will not work in the browser.</p>";
  // Add the document title using javascript when the window loads.
  $browser_output .= "<script>window.onload = function(){document.title='$title';}</script>";
  // Output the combined string.
  return $browser_output;
}
```

注意到这里存在一个**eval**方法

![](./images/image-153.png)

这个工具必须要在**/var/www/html**中启动才行！

![](./images/image-154.png)

然后开启**bash**就行了

![](./images/image-155.png)

## Summary

`User`：**/.git**泄露拿到源码，遍历文件查找到了数据库的密码，以及一个**tiffany**用户。进入到后台可以上传一个**module**，这里我是直接到[Modules for Backdrop CMS | Backdrop CMS](https://backdropcms.org/modules)中下载然后修改源码的，反弹**shell**拿到**www-data**的权限。

`Root`：**bee**是**Backdrop CMS** 的一个 **命令行工具**，需要在其主目录下使用。通过命令行执行**php**的**system**函数，获取到**root**的**bash**。
