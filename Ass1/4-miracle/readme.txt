first i disassembled the function into a file with

set logging on
disassemble authenticate
set logging off


then i located all occurances of the breakpoint and interesting part with 

cat gdb.txt | grep -E "call   0x401050|cmp"

i followed this by piping it into awk with 

| awk '/call   0x401050/ { count++ } /cmp/ { print count; exit } '

in order to find how many continue instructions i needed.
