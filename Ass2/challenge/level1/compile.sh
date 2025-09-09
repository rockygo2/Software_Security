#!/bin/bash

set -e

LEVEL=1
CFLAGS=""
: ${DIR=/var/challenge/level$LEVEL}
cc $CFLAGS $DIR/$LEVEL.c -o $LEVEL
