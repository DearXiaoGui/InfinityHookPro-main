extern MyHalpHvCounterQueryCounterAddr:QWORD
extern Original_HalpHvCounterQueryCounter:QWORD
extern circularKernelContextLogger:QWORD

.code
checkLogger PROC

correctLogger:
	push rcx
	mov rcx,rsp
	call MyHalpHvCounterQueryCounterAddr
	pop rcx
exit:
	mov rax, Original_HalpHvCounterQueryCounter
	jmp rax
checkLogger ENDP
end