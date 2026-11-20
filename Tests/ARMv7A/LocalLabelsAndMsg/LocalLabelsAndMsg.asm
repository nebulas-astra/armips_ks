.armv7a
.create "output.bin",0x1000

.macro SpinLoop
@@loop:
	nop
	b @@loop
.endmacro

.arm
@StaticArm:
@@LocalArm:
	add r0,=@StaticArm
	add r1,=ArmTarget
	b @@LocalArm
	.msg "Hi"
ArmTarget:
	nop

.thumb
@StaticThumb:
@@LocalThumb:
	SpinLoop
	SpinLoop
	add r0,=ThumbTarget
	add r1,=@StaticThumb
	b @@LocalThumb
	.msg "Hi"
ThumbTarget:
	bx lr

.close
