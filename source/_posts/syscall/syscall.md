---
title: 系统调用号
tags:
    - syscall
    - pwn
categories:
    - 知识梳理
cover: /img/达令.png
---
# syscall 知识梳理

##  系统调用号

### 32位
```
read 3     eax=3  ebx=fd ecx=buf edx=size
write 4    eax=4  ebx=fd ecx=buf edx=size
open 5     eax=5  ebx=path ecx=flags edx=mode
close 6    eax=6  ebx=fd
execve 11  eax=0xb  ebx="/bin/sh\x00" ecx=0 edx=0

int 0x80
```
### 64位
```
read 0     rax=0 rdi=fd rsi=buf rdx=size
write 1    rax=1 rdi=fd rsi=buf rdx=size
open 2     rax=2 rdi=patch rsi=flags rdx=mode
close 3    rax=3 rdi=fd 
execve 59  rax=0x3b rdi="/bin/sh\x00" rsi=0 rdx=0

sys_call
```
