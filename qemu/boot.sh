#!/bin/sh

qemu-system-x86_64 -initrd rootfs.cpio \
    -kernel bzImage \
    -append 'console=ttyS0 root=/dev/ram rw oops=panic panic=1' \
    -m 128M \
    --nographic  \
    -s

