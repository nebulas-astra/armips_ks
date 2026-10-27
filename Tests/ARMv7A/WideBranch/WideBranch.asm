.armv7a
.create "output.bin",0

; BL and BLX only have a 32-bit Thumb encoding. GNU-style .w spellings, as
; produced by disassemblers, must assemble to the same instructions as the
; plain mnemonics.
.thumb
start:
	BL.W	target
	bl	target
	BLX.W	arm_target
	blx	arm_target
	nop
target:
	b.w	start
	.byte	0x00, 0x00
arm_target:
	nop

.close
