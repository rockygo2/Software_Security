#!/bin/bash
set -e

LEVEL=7
CFLAGS="-no-pie -fno-stack-protector -z execstack -mpreferred-stack-boundary=4"
: ${DIR=/var/challenge/level$LEVEL}
cc $CFLAGS $DIR/$LEVEL.c $DIR/scenes.c -o $LEVEL
