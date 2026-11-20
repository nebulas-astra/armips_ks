.armv7a
.create "output.bin",0x1000

.definelabel UseAlt,1

.thumb
	itt eq
	movweq r0,Target
	bleq.w Target

	it.n ne
.ifdef UseAlt
	movne r1,#5
.else
	movne r1,#9
.endif

	it eq
	addeq r2,r2,#(org(Target) - 0x1010)
Target:
	bx lr

.close
