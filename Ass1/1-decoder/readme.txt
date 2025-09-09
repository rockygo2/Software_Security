[PART 1]
[1.1]
First we disassemble main and can see the size is 20 due to the line 
0x00000000004011ad <+49>:	cmp    rax,0x14

[1.2]
encoded shows in the script.c file and is matched in gdb

[1.3]
decode shows in the script.c file and is matched in gdb


[PART 2]
[2.1]
we disassemble main and put our breakpoint on the assembly instruction after it

[2.2]
We pritf $rax as $rax contains the return value of decoded. we also choose to print a character as we need it in human readable format

[Part 3]
[3.1]
We run the program manually one at a time in order to get the full flag starting withj run AAAAAAAAAAAAAAAAAAA and appending to the start for every correct character

run flag{H4shItN3xtT1me}