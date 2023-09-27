DEFAULT REL
SECTION .text

global ASM_PFX(DisableCet)
ASM_PFX(DisableCet):
	; Pop pushed data for 'call'
	mov rax, 1
	incsspq rax

	mov rax, cr4
	btr eax, 23					; clear CR4_CET
	mov cr4, rax
	ret

global ASM_PFX(EnableCet)
ASM_PFX(EnableCet):
	mov rax, cr4
	bts eax, 23					; set CR4_CET
	mov cr4, rax

	; Use jmp to skip check for 'ret'
	pop rax
	jmp rax
