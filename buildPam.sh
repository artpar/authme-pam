#!/bin/bash
rm -fr authme_pam.o

gcc  -fPIC -fno-stack-protector  -lcurl -c src/authme_pam.c

sudo ld  -lcurl -x --shared -o /lib/security/authme_pam.so authme_pam.o

