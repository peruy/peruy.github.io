---
title: tcache的发展历程
tags:
    - 堆利用
    - tcache 
categories:
    - 学习笔记
cover: /img/紫发.png
---
# tcache的发展历程

## 前言

经建议，笔者打算参加一次xctf 的分站赛，为此开始备注。遂开始复现往届比赛赛题。先从这次sekaictf-2025开始。这是从第一题开始的分析与延伸。

## tcache的引入及更新

### 2.26-2.27
首先，tcache 在glibc 2.26 版本登场，其目的是为了加快堆块的管理。因此在没有作安全的检测，也为之后的利用埋下了隐患。
#### 相关源码
```c
#define TCACHE_MAX_BINS 64
typedef struct tcache_perthread_struct {
    char          counts[TCACHE_MAX_BINS];   /* 0x00 */
    tcache_entry *entries[TCACHE_MAX_BINS];  /* 0x40 */
} tcache_perthread_struct;                   /* 总长 0x290 */

typedef struct tcache_entry {
    struct tcache_entry *next;   /* 仅 8 字节 */
} tcache_entry;
```

在glibc2.26 和 glibc2.27 的版本中，没有任何安全检测的手段。可以修改tcache chunk(指链入tache bins 中的堆块) 的next 字段，完成任意地址分配。

当然，为了便于tcache 的管理，加入了`tcache_perthread_struct` 结构体.
`counts` 数组,用来记录每个大小的`tcache bins` 中的数量
`entries`数组用来记录每个`tcache chunk`的`next`字段的地址
同理,我们可以修改`counts` 和`entries`来欺骗系统,完成任意地址分配.

因为没有任何检测,所以我们可以完成`double free`,甚至你可以把同一个堆块连续free 7次,把tcache bins 填满.

### 2.28 第一次补丁

显然,注意到了`double free`的利用过于easy, 于是`tcache` 迎来了他的第一次更新, 添加了 key 这个变量. 在2.29 版本没有什么改动
#### 相关源码
```c
typedef struct tcache_entry {
    struct tcache_entry *next;
    struct tcache_perthread_struct *key;   /* ← 指向 tcache 本身 */
} tcache_entry;


static void
tcache_put (tcache_perthread_struct *tcache, tcache_entry *e, size_t tc_idx)
{
    /* 1. 先检查链表长度 */
    if (tcache->counts[tc_idx] >= TCACHE_MAX_BINS)
        return;

    /* 2. 关键：double-free 检测 */
    if (__glibc_unlikely (e->key == tcache))
        malloc_printerr ("double free or corruption (fasttop)");

    /* 3. 把 chunk 插入链表头 */
    e->key = tcache;                  // 标记“我已进 tcache”
    e->next = tcache->entries[tc_idx];
    tcache->entries[tc_idx] = e;
    tcache->counts[tc_idx]++;
}
```

简单解析一下:
1. key字段开始不作设置
2. 当堆块通过 `double-free`时,也就是`e->key!=tcache`时,`e`进入`tcache bins`中,并把`key`设置为`tcahche`
3. 那么下次`free(e)`,就会检测到这个的key,从而判断是否`double-free`.

但是,想要绕过也非常简单.想要继续`double free`,只要能修改到key字段就可以继续这个利用.
而修改next的方法可以照旧.

这个检测,仅仅是为了针对`double free`而已,所以局限很大.对安全方面的加强有点,但多.

### 2.30微调-counts加宽

没有大改,也不知道为啥要这么改动.效果不知道,目的不知道. 

```c
#define TCACHE_MAX_BINS 64
typedef struct tcache_perthread_struct {
    uint16_t          counts[TCACHE_MAX_BINS];   /* 0x00 */
    tcache_entry *entries[TCACHE_MAX_BINS];  /* 0x80 */
} tcache_perthread_struct;   
```

在2.26 和 2.27 中, 这个字段是char 类型,也就是只有8位, 1字节.   现在加宽, 改为16位, 2字节.
以后修改 entries 数组时,需要把偏移调整一下.

### 2.32小加强-entries加密

entries的加密,让之前直接修改next 的利用变得稍微困难了一点. 我们必须明确一个点,tcache bins 中, chunk 的 下一个堆块 原本是有next 决定的,因为entries 就是 直接 用next的值. 
但是现在不是了, entries 是 (&next>>12) ^ next . 但是因为加密的算法是固定的,所以 我们只要能泄露堆地址,就可以继续伪造.

#### 相关源码
```c
#define PROTECT_PTR(pos, ptr) \
        ((__typeof (ptr)) (((size_t) pos >> 12) ^ (size_t) (ptr)))
```

假设 你要写入的 地址是 target , 你现在修改的chunk 的 next 指针的地址是addr. 那么你实际需要写入next 的值是 (addr>>12) ^ target. 

计算同样非常简单.

### 2.34小加强-key随机化

```c
static __thread tcache_perthread_struct *tcache = NULL;
static __thread size_t tcache_key = 0;   /* ← 不再是 tcache 地址，而是随机值 */
```

虽然是小加强, 因为此时要获取key似乎只能爆破.但是我不明白,因为对key字段的检测,只有在这个堆块被free 要进入tcache bins 时.

也就是说,其实很多时候根本触发不了这个检测.

## 利用手法

###  参考文章
[[原创]tcache bin利用总结-Pwn-看雪-安全社区|安全招聘|kanxue.com](https://bbs.kanxue.com/thread-275302.htm#msg_header_h2_4)

