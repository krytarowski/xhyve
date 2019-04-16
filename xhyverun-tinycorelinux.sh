#!/bin/sh

PATH="build/Release:build:$PATH"

xhyve \
    -a nvmm \
    -m 1G \
    -l com1,stdio \
    -f kexec,test/vmlinuz,test/initrd.gz,"earlyprintk=serial console=ttyS0"
