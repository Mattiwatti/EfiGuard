.code

DisableCet PROC
	; Pop pushed data for 'call'
	mov rax, 1
	incsspq rax

	mov rax, cr4
	btr eax, 23					; clear CR4_CET
	mov cr4, rax
	ret
DisableCet ENDP

EnableCet PROC
	mov rax, cr4
	bts eax, 23					; set CR4_CET
	mov cr4, rax

	; Use jmp to skip check for 'ret'
	pop rax
	jmp rax
EnableCet ENDP

end
