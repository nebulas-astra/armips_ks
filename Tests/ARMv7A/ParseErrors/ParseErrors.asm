.armv7a
.create "output.bin",0

.arm
	mov r0,org(
	ldr r0,=1
	ldr r1,=2

.if 0
	.pool
	ldr r2,=3
	mov r0,org(
.endif

.close
