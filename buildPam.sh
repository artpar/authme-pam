#!/bin/bash

gcc -fPIC -fno-stack-protector -c src/mypam.c

sudo ld -x --shared -o /lib/x86_64-linux-gnu/security/mypam.so mypam.o

rm mypam.o
