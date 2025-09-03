set logging file /dev/null
set logging redirect on
set logging enabled on
set max-value-size unlimited
# For this challenge, please replace any occurence of `<TODO>` after this line with your answer.
# There is no need to change anything else, unless otherwise specified.
# Make sure that the final script contains valid GDB commands before submitting, 
# and that it works properly, by running `gdb cpu --batch -x script.gdb`.


# This binary seems to emulate the CPU of an old computer.
# The CPU can operate on a 16-bit address space, and has 8-bit registers that can also be combined to 16-bit registers for some instructions.
# This program contains a bug: it is possible to push the Stack Pointer of the emulated CPU
# outside of the 16-bit address space, and write into the stack of the program itself.
# The goal of this challenge will be to exploit this bug.


# [Part 1]
# The binary contains a normally-unreachable function called `print_flag`. The goal will be to reach this function using an exploit.
# To exploit it, we will need to write a small program that the emulated CPU understands. Before you start, we recommend looking through
# the binary with GDB to find the registers and instruction set of the emulated CPU.
# The opcode of an instruction is equal to its index in the array of instructions. 
# Some instructions may require parameters, and thus are longer than one byte.

# Let's first jump to a location after the emulated CPU is initialized, to look at the stack layout.
break start_cpu
run

# [1.1] The emulated CPU contains a 16-bit integer that functions as an Instruction Pointer/Program Counter,
# which is used to look up instructions stored within the 16-bit address space of the CPU 
# (which is emulated as a large array of bytes that is part of the CPU on the stack). 
# What is the initial value of the emulated CPU's Program Counter?
set $program_counter_init = <TODO>

# [1.2] Find the correct opcodes to exploit this bug, and write them into the emulated CPU's memory array.
# Use GDB to find which instructions the CPU supports, and what their opcodes are.
# Use this to push the emulated CPU's Stack Pointer outside of the CPU's memory, and into the programs memory,
# and overwrite the return pointer there.
# Here are some steps you can follow to find the right instructions:
# - First, we need to move the Stack Pointer to the start of the memory array.
# - Then, we need to push values to the stack. These values should combine to form the address of the `print_flag` function.
# - Finally, we need to make the program return to the overwritten address. There are a few invalid instructions that can make the CPU exit.
# For this task, you are only allowed to use GDB commands to write bytes inside the CPU's 16-bit address space.
# You can do this like so (as an example):
#   `set cpu.memory[0x1234] = 0x56`
<TODO>

continue

# [1.3] If you did this correctly, the program will jump to the unreachable function, and will print out the flag.
# What is the flag? Put your answer in double quotes (") like a string.
set $flag = <TODO>
