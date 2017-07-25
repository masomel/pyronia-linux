#!/bin/bash

OUT=$(./$1)

if [ $? -ne 0 ]
then
    echo "$1 failed: $OUT"
    exit
fi

echo "$1 passed"
