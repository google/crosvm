.section .boot, "awx"
.global _start
.code64
# crosvm starts execution at 0x200 offset from the beginning
.fill 0x200

_start:
    lea rsp, _stack_end

    jmp main


