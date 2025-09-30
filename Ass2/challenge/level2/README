We run 
```
./2 ../../../../../../usr/local/bin/l33t
```
this works as 
```
sprintf(path, "%s%d%s%s", PREFIX_DIR, getegid() - 3000, DEVBIN_DIR, argv[1]);
```
uses an absolute file location without filtering for LFI vulnerabilities. All we have to do is search for the location of l33t which we find at ```/usr/local/bin/l33t```. We then need to go backwards enough folders in order to get to the root folder before trying to execute l33t in order for it to work