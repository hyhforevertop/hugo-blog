---
title: "EP-WinServerCA"
date: 2024-11-17
categories: 
  - "engineering-practice"
tags: 
  - "windows"
  - "工程实践"
---

## 前言

这个主机毫无新意，这篇文章我都不想写，攻破这个主机的方法和前面`8089`是一模一样

## PTH攻击

按道理来说，拿下域控的`Administrator`之后，整个域基本上就可以打穿了。

这台主机依旧是使用`pass-the-hash`攻击

![](./images/image-54.png)

只需要修改一下IP就能进去了

在`Administrator`目录下拿到flag

![](./images/image-55.png)

本次工程实践到此结束
