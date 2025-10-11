---
title: tcache_stashing_attack
tags:
    - 堆利用
    - tcache 
categories:
    - 学习笔记
cover: /img/紫发.png
---
# tcache_stashing_attack

## 前言

>虽说已经准备考公了，但是自己还是喜欢打pwn ， 感觉还是不能放弃。
>那就继续前进

## 原理

```c
while ( tcache->counts[tc_idx] < mp_.tcache_count
    && (tc_victim = last (bin) ) != bin) //验证取出的Chunk是否为Bin本身（Smallbin是否已空）
{
 if (tc_victim != 0) //成功获取了chunk
 {
     bck = tc_victim->bk; //在这里bck是fake chunk的bk
     //设置标志位
     set_inuse_bit_at_offset (tc_victim, nb);
     if (av != &main_arena)
         set_non_main_arena (tc_victim);
 
     bin->bk = bck;
     bck->fd = bin; //关键处
 
     tcache_put (tc_victim, tc_idx); //将其放入到tcache中
 }
}
```


还是先看源码吧,这个触发条件就是,tcache bins 里有堆块,但是 没有从tachce 申请, 那么就会触发这段代码.

触发之后,它会把当前`smallbin`中的堆块全都放进`tcache bins`,同时还不会检查 bk.

那么如果我修改`small bin` 中最后的堆块的`bk` 为一个 `fake chunk`, 并且将`fake chunk` 的 `bk` 指针修改为 `target - 0x10`, 那么经过上面的代码,就会在`target`处写入这个 `small bin`的地址.

而且之后,`fake chunk` 会进入到`tcache bin` ,可以直接申请出来.

通过这个方法,可以做两件事情,一是往一个地址里写入`small bins` 的地址,一个是可以申请一块`fake chunk` 

在unsorted 失效之后,这个方法,使用的更为广泛.

## 流程

介绍完了,原理之后,我们来看具体的一个利用流程.具体该如何操作呢?



1. 先把`tcache bins` 填充 到有5个堆块, 然后相应大小的`small bin`中有2个堆块.
>`tcache bin`的填充,不多说.`small bin`,可以通过切割`unsorted bin` 控制里面的大小,然后再申请大堆块,迫使其放入`tcache bin`


2. 假设small bin中的结构如下:
>chunk A: fd=main_arena+88 , bk=B
>chunk B: fd=A,bk=main_arena+88
>那么,接下来如果使用calloc 申请 ,会先申请出A堆块,然后对B做上述处理.


3. 那么,我们提前修改,B中的bk为fake chunk 的地址,同时确保,这个fd可写.
>chunk B: fd=A,bk=fake chunk
>fake chunk:fd=随便 bk=target-0x10
>这个target 要可写


4. 那么,在之后calloc ,会对这两个堆块都走上述代码.
>申请时,A被申请出去,此时smallbin fd 链只有 B,bk 链里有fake chunk 和它的bk.
>因为代码里是取last(),也就是从bk 链里取,所以先出理b.那么就有 fake chunk->fd=B
>然后处理fake chunk, 所以有target=fake chunk

