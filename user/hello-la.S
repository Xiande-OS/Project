# Minimal freestanding LoongArch64 userspace test program.
#
# Embedded as the `hello` binary for loongarch64 kernel builds so the LA
# port can exercise user mode + the syscall path without a disk. Linux
# generic syscall ABI: number in $a7 ($r11), args in $a0.. ($r4..),
# `syscall 0`, return in $a0. __NR_write = 64, __NR_exit = 93.

    .equ msg_len, 31

    .section .text
    .globl _start
_start:
    li.w      $a0, 1
    la.local  $a1, msg
    li.w      $a2, msg_len
    li.w      $a7, 64
    syscall   0

    li.w      $a0, 0
    li.w      $a7, 93
    syscall   0

1:  b         1b

    .section .rodata
msg:
    .ascii "hello from loongarch userspace\n"
