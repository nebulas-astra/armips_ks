.armv7a
.create "output.bin",0x2000

.arm
d1:
	vadd.f64 d0,d1,d2
c1:
	mcr p15,0,r0,c1,c0,0
sy:
	dmb sy
i:
	cpsie i
eq:
	b d1
	movw r0,c1
lsl:
	add r1,r2,r3,lsl #2

.thumb
	it eq
	addeq r0,r1,r2
	b eq

.close
