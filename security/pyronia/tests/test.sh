#!/bin/bash

OUT=$(./$1)
RET=$?

if [ $RET -ne 0 ]; then
    echo "$1 failed with return value $RET: $OUT"
    exit
fi

echo "$1 passed with return value $RET"
