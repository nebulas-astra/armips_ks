.armv7a
.create "output.bin",0x1000

.arm
	b #ArmTarget
	b ArmTarget
	bl #ArmTarget
	nop
ArmTarget:

.thumb
	b #ThumbTarget
	b ThumbTarget
	b.w #ThumbTarget
	bl #ThumbTarget
	nop
ThumbTarget:
	bx lr

.close
