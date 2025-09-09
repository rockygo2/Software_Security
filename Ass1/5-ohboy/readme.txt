[Part 1]
[1.1]
first we find the program counter starts at 1 by jumping step by step through execute_instruction + 
read_byte in where this line 0x00000000004014dd <+28>:	movzx  eax,BYTE PTR [rdx+rax*1]
exposes what PC  we are starting with

[1.2]
we find what type of emulator it is firstly by dumping the instructions that 
i dumped all the instructions with x/100gx 0x00000000004023e1
I followed this by searching up the instruction symbols i found until i stumbled upon the matching documentation below
https://map.grauw.nl/resources/z80instr.php

I then used the information given in these documents in order to create the payload
we set our SP to the start (0000) we then push 2 empty bytes in order to reach the region which we can overwrite
we then overwrite it with the correct address
since overwriting to the start of printflag causes a stack alignment error we skip 
the push rbp instruction in order to fix the stack allignment 


set $flag = flag{ItD03sntRunD00m}
