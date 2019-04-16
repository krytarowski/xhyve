#!/bin/sh

PATH="build/Release:build:$PATH"

xhyve \
    -a nvmm \
    -A \
    -s 0:0,hostbridge \
    -s 31,lpc \
    -m 800M \
    -l com1,stdio \
    -f kexec,test/vmlinuz,test/initrd.gz,"earlyprintk=serial console=ttyS0"
