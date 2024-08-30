; Hook.asm
; This MASM file defines a transparent hook for Windows and NT API function

OPTION PROLOGUE:NONE     ; Disable automatic prologue generation
OPTION EPILOGUE:NONE     ; Disable automatic epilogue generation

EXTERN GenericDetour:PROC ; Declare GenericDetour as an external procedure

; Declare the external function signature (used by the C++ code)
PUBLIC GenericHookWrapper

.code           ; Start of the code segment

; The GenericHook function accepts any number of arguments and will call GenericDetour

GenericHookWrapper PROC
    ; Save all registers and the stack state
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    ; Align stack to 16 bytes before calling the C++ function
    sub rsp, 20h           ; Ensure stack is 16-byte aligned for the call
    call GenericDetour

    ; Restore the stack and registers
    add rsp, 20h
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax

    ret
GenericHookWrapper ENDP
END
