#!/bin/sh

export BOOTVOLUME="/public/FreeBSD-12.0-RELEASE-amd64-bootonly.iso"
IMG="<path of disk image for FreeBSD>"

export PATH="build/Release:build:$PATH"
export LD_LIBRARY_PATH=/usr/local/lib

#lldb --
xhyve \
    -a nvmm \
    -m 2G \
    -c 2 \
    -l com1,stdio \
    -f fbsd,test/userboot.so,$BOOTVOLUME,""
