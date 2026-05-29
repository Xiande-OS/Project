# Freestanding LoongArch64 "hello" — write(1,msg,len) then exit_group(0).
# Linux LA syscall ABI: nr in $a7, args $a0..$a5, `syscall 0`, ret in $a0.
    .section .rodata
msg:
    .ascii  "hi from loongarch userspace\n"
msg_end:
    .set    msglen, msg_end - msg

    .section .text
    .globl _start
_start:
    # write(1, msg, len)
    li.d    $a0, 1                 # fd = stdout
    la.local $a1, msg             # buf
    li.d    $a2, msglen           # count
    li.d    $a7, 64               # __NR_write
    syscall 0

    # exit_group(0)
    li.d    $a0, 0
    li.d    $a7, 94               # __NR_exit_group
    syscall 0

1:  b       1b
