MSR_S_CET					EQU 6A2h
MSR_S_CET_SH_STK_EN			EQU 1
CR4_CET						EQU (1 SHL 23)
N_CR4_CET					EQU 23

.code

align 16
AsmDisableCet PROC
	mov ecx, MSR_S_CET
	rdmsr
	test al, MSR_S_CET_SH_STK_EN
	jz @F						; if z, shadow stack not enabled

	; Pop pushed data for 'call'
	mov rax, 1
	incsspq rax

@@:
	mov rax, cr4
	btr eax, N_CR4_CET			; clear CR4_CET
	mov cr4, rax
	ret
AsmDisableCet ENDP

align 16
AsmEnableCet PROC
	mov rax, cr4
	bts eax, N_CR4_CET			; set CR4_CET
	mov cr4, rax

	; Use jmp to skip check for 'ret'
	pop rax
	jmp rax
AsmEnableCet ENDP

end
