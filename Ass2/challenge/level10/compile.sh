#!/bin/bash

set -e

LEVEL=10
CFLAGS="-pie -fPIC -fstack-protector -Wl,-z,now -Wl,-z,relro -D_FORTIFY_SOURCE=2 -O1"
: ${DIR=/var/challenge/level$LEVEL}
cc $CFLAGS $DIR/$LEVEL.c $DIR/js-codegen.c $DIR/js-compiler.c $DIR/js-expressions.c $DIR/js-scope.c $DIR/js-tokenizer.c -o $LEVEL
