.armv7a
.create "output.bin",0x81600000

.definelabel ExternalTarget,0x814C1E48

.macro LoadImm32,reg,value
	movw reg,value
	movt reg,(value) >> 16
.endmacro

.thumb
	LoadImm32 r0,org(LabelA)
	LoadImm32 r1,ExternalTarget
LabelA:
	LoadImm32 r2,LabelA + 4
	b.w AfterNop
	nop
AfterNop:
	push {r0-r3,lr}
	pop {r0-r3,pc}

.close
