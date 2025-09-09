#!/bin/bash

set -e

LEVEL=8
CFLAGS="-no-pie -fno-stack-protector -z execstack -mpreferred-stack-boundary=4"
: ${DIR=/var/challenge/level$LEVEL}
cc $CFLAGS $DIR/$LEVEL.c $DIR/mymalloc.c -o $LEVEL
