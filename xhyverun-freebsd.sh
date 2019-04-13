#!/bin/sh

BOOTVOLUME="/public/FreeBSD-12.0-RELEASE-amd64-bootonly.iso"
IMG="<path of disk image for FreeBSD>"

PATH="build/Release:build:$PATH"

xhyve \
    -a hax \
    -A \
    -m 2G \
    -c 2 \
    -l com1,stdio \
    -f fbsd,test/userboot.so,$BOOTVOLUME,""
