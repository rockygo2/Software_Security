#!/bin/bash

set -e

LEVEL=3
CFLAGS="-g"
: ${DIR=/var/challenge/level$LEVEL}
cc $CFLAGS $DIR/$LEVEL.c -o $LEVEL
