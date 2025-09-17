#!/bin/bash

set -e

LEVEL=4
CFLAGS="-g -fno-stack-protector -z execstack -mpreferred-stack-boundary=4 -fno-builtin"
: ${DIR=level$LEVEL}
cc $CFLAGS $LEVEL.c -o $LEVEL
