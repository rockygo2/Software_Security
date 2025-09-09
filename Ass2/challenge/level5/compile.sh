#!/bin/bash

set -e

LEVEL=5
CFLAGS="-fno-stack-protector -mpreferred-stack-boundary=4 -Wno-format-security -Wl,-z,relro,-z,now,-z,execstack"
: ${DIR=/var/challenge/level$LEVEL}
cc $CFLAGS $DIR/$LEVEL.c $DIR/aes.c -o $LEVEL
