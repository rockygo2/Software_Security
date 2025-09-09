#!/bin/bash

set -e

LEVEL=2
CFLAGS=""
: ${DIR=/var/challenge/level$LEVEL}
cc $CFLAGS $DIR/$LEVEL.c -o $LEVEL
