[Part 1]
[1.1]
first i disassembled the function into a file with

set logging on
disassemble authenticate
set logging off


then i located all occurances of the breakpoint and interesting part with 

cat gdb.txt | grep -E "call   0x401060|cmp"

i followed this by piping it into awk with 

| awk '/call   0x401060/ { count++ } /cmp/ { print count; exit } '

in order to find how many continue instructions i needed.

[1.2]
We stop at 0x46b91f <authenticate+436053> mov    eax, DWORD PTR [rip+0xd717] 
we do 0xd717 + the current RIP + 6 as it starts at the next instruction which is 6 away
We can also see the target value in the cmp    eax, 0x1020304 function

[Part 2]
[2.1]
I notice that the break calls at 0x401060 after the program fails prints "Login failed" so we check for the first occurance of this.
When we find this we then go back by 0x3D as that is the distance this location will be away from where we exploited the program previously

FLAG: flag{3v3ryD4y154M1r4cl3}