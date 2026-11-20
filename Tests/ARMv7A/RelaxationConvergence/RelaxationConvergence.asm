.armv7a
.create "output.bin",0x1000

.thumb
	mov r0,(org(Target) & 2) * 0x100
Target:
	nop

.close
