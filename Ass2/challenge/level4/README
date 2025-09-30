We write 40 characters into ```char user[40]```
so that when ```strcat(greeting, params.user);``` is called since there is no null byte params.user gets copied alongside whatever is next on the stack which happens to be host. Host is then copied alongside user. We put 53 characters into host so we can reach the return pointer.

We do ```shellcode[:40]``` because orignally i wanted to write the payload onto the stack then jump to it but i realised just doing an environment variable is easier so i switched it to but the program does work as stated above

We also surround our shellcode_full with '''\xbb''' so it is easier to find when dumping the environment hex and use shellcraft because we are lazy