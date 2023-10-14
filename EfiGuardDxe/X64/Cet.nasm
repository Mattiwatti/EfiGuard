%define MSR_S_CET						0x6A2
%define MSR_S_CET_SH_STK_EN				0x1
%define CR4_CET							(1 << 23)
%define N_CR4_CET						23

DEFAULT REL
SECTION .text

align 16
global ASM_PFX(AsmDisableCet)
ASM_PFX(AsmDisableCet):
	mov ecx, MSR_S_CET
	rdmsr
	test al, MSR_S_CET_SH_STK_EN
	jz .SsDone					; if z, shadow stack not enabled

	; Pop pushed data for 'call'
	mov rax, 1
	incsspq rax

.SsDone:
	mov rax, cr4
	btr eax, N_CR4_CET			; clear CR4_CET
	mov cr4, rax
	ret

align 16
global ASM_PFX(AsmEnableCet)
ASM_PFX(AsmEnableCet):
	mov rax, cr4
	bts eax, N_CR4_CET			; set CR4_CET
	mov cr4, rax

	; Use jmp to skip check for 'ret'
	pop rax
	jmp rax
