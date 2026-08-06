.data
    ssn              DWORD 0
    gadget_addr      QWORD 0

.code
    SetSSN PROC
        mov ssn, ecx
        ret
    SetSSN ENDP

    SetGadget PROC
        mov gadget_addr, rcx
        ret
    SetGadget ENDP
    

    ;Indirect Syscall 구현
    AllocSyscall PROC
        mov r10, rcx            ; 첫 번째 인자 보존
        mov eax, ssn
        jmp QWORD PTR [gadget_addr]
        ret
    AllocSyscall ENDP

    WriteSyscall PROC
        mov r10, rcx            ; 첫 번째 인자 보존
        mov eax, ssn
        jmp QWORD PTR [gadget_addr]
        ret
    WriteSyscall ENDP


    ;Direct Syscall 구현
    ;AllocSyscall PROC
    ;    mov r10, rcx            ; 첫 번째 인자 보존
    ;    mov eax, ssn
    ;    syscall
    ;    ret
    ;AllocSyscall ENDP

    ;WriteSyscall PROC
    ;    mov r10, rcx            ; 첫 번째 인자 보존
    ;    mov eax, ssn
    ;    syscall
    ;    ret
    ;WriteSyscall ENDP
    

end
