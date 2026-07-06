.code

EXTERN g_ntdllGadget:QWORD

IndirectSyscall5 PROC
    mov r10, rcx
    mov eax, ecx
    mov r11, g_ntdllGadget
    jmp r11
IndirectSyscall5 ENDP

IndirectSyscall6 PROC
    mov r10, rcx
    mov eax, ecx
    mov r11, g_ntdllGadget
    jmp r11
IndirectSyscall6 ENDP

HeavensGateEntry PROC
    push rbp
    mov rbp, rsp
    sub rsp, 40
    push rsi
    push rdi
    push rbx
    
    mov eax, 33h
    push rax
    lea rax, [heavens_gate_64]
    push rax
    retfq
    
heavens_gate_64:
    mov rax, rcx
    mov rcx, rdx
    mov rdx, r8
    mov r8, r9
    
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    call rax
    
    add rsp, 32
    pop rbp
    
    mov rbx, [rsp + 48]
    mov rdi, [rsp + 40]
    mov rsi, [rsp + 32]
    add rsp, 40
    pop rbp
    ret
HeavensGateEntry ENDP

HeavensGateExit PROC
    mov eax, 23h
    push rax
    lea rax, [heavens_gate_32]
    push rax
    retfq
    
heavens_gate_32:
    ret
HeavensGateExit ENDP

END