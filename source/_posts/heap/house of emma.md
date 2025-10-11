---
title: house of emma
tags:
    - House of XXX
    - IO
categories:
    - 学习笔记
cover: /img/紫发.png
---
# house of emma

## 前言

看完了kiwi，现在来看看emma，这两个手法的思路大差不差。但是emma有一道湖湘杯的例题，学习起来会方便很多
## 原理

### 源码

核心同样是kiwi当中的那个断言，但是修改的思路转变了。在kiwi中是修改虚表中某个函数指针，在emma中则是修改vtable的地址。这个地址是--`_IO_cookie_jumps`

```c
/* Special file type for fopencookie function.  */
struct _IO_cookie_file
{
  struct _IO_FILE_plus __fp;
  void *__cookie;
  cookie_io_functions_t __io_functions;
};

typedef struct _IO_cookie_io_functions_t
{
  cookie_read_function_t *read;        /* Read bytes.  */
  cookie_write_function_t *write;    /* Write bytes.  */
  cookie_seek_function_t *seek;        /* Seek/tell file position.  */
  cookie_close_function_t *close;    /* Close file.  */
} cookie_io_functions_t;

static ssize_t
_IO_cookie_read (FILE *fp, void *buf, ssize_t size)
{
  struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;
  cookie_read_function_t *read_cb = cfile->__io_functions.read;
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE (read_cb);
#endif

  if (read_cb == NULL)
    return -1;

  return read_cb (cfile->__cookie, buf, size);
}

static ssize_t
_IO_cookie_write (FILE *fp, const void *buf, ssize_t size)
{
  struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;
  cookie_write_function_t *write_cb = cfile->__io_functions.write;
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE (write_cb);
#endif

  if (write_cb == NULL)
    {
      fp->_flags |= _IO_ERR_SEEN;
      return 0;
    }

  ssize_t n = write_cb (cfile->__cookie, buf, size);
  if (n < size)
    fp->_flags |= _IO_ERR_SEEN;

  return n;
}

static off64_t
_IO_cookie_seek (FILE *fp, off64_t offset, int dir)
{
  struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;
  cookie_seek_function_t *seek_cb = cfile->__io_functions.seek;
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE (seek_cb);
#endif

  return ((seek_cb == NULL
       || (seek_cb (cfile->__cookie, &offset, dir)
           == -1)
       || offset == (off64_t) -1)
      ? _IO_pos_BAD : offset);
}

static int
_IO_cookie_close (FILE *fp)
{
  struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;
  cookie_close_function_t *close_cb = cfile->__io_functions.close;
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE (close_cb);
#endif

  if (close_cb == NULL)
    return 0;

  return close_cb (cfile->__cookie);
}
```

在emma的利用中,主要就是利用`_IO_cookie_read`,而在这个函数的开始几行,是对`rax` 加密,然后`call rax`,加密是另一个操作数是`fs:[0x30]`,这个指针可以利用`large bin attack` 修改.

如果题目开启沙箱禁用了`execve`,那就需要`setcontext`中的`gadget`了
## 利用思路

1. 利用`largebins attack`等手段,修改掉`stderr`,然后伪造`fake io`
2. 利用`setcontext+61`控制程序的执行流.
3. 如果程序没有开启沙箱的话,可以考虑用`system`来`get shell`

## 例子

[湖湘杯-2021-house of emma](https://peruy.github.io/2025/10/06/ctf%E6%AF%94%E8%B5%9B%E5%A4%8D%E7%8E%B0/%E6%B9%96%E6%B9%98%E6%9D%AF-2021-house%20of%20emma/)
