; Hook.asm
; This MASM file defines a transparent hook for Windows and NT API functions

OPTION PROLOGUE:NONE     ; Disable automatic prologue generation
OPTION EPILOGUE:NONE     ; Disable automatic epilogue generation

EXTERN MonitorHook:PROC  ; Declare MonitorHook as an external procedure

; Declare the external function signature (used by the C++ code)
PUBLIC GenericHookWrapper

.code           ; Start of the code segment

GenericHookWrapper PROC
    call MonitorHook       ; Call the MonitorHook, which inspects the current thread context
    ret
GenericHookWrapper ENDP

END