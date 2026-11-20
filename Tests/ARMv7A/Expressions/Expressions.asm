.armv7a
.create "output.bin",0x1000

.definelabel SymVal,0x12345678

.arm
ArmBase:
	mov r0,#(1 == 1)
	mov r1,#(ArmBase == 0x1000 ? 7 : 9)
	mov r2,#(1 == isThumb())
	mov r3,#((0FFh >> 2) | (0FFh << 30))
	mov r4,1.0
	vmov.f32 s0,#1.0
	movw r5,:lower16:SymVal
	movt r5,:upper16:SymVal
	movw r6,.
	movweq r7,SymVal

.thumb
ThumbBase:
	mov r0,#(isThumb() == 1)
	add r0,#1
	add.w r0,r0,#1
	sub r1,r2,#3
	and r0,r1
	movw r2,:lower16:SymVal
	movt r2,:upper16:SymVal

.close
