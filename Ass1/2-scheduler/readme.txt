Part[1]
[1.1]
First we stop at the function call to fgets at line main+192 
and then skip forward by 5 in order to get the next instruction
   0x00000000004013c0 <+192>:	call   0x401120
   0x00000000004013c5 <+197>:	lea    rax,[rbp-0x20]

Part[2]
[2.1]
we start by doing watch contention > 8 as if if (contention <= TOLERANCE) {} then the if (len > BUFFER) is skipped and we can input the payload
we then disable 1 so that we can put in our payload
followed by reanabling 1 in order to continue automatically doing fgets calls. 
We also disable 2 after the payload is inputted as we no longer need it