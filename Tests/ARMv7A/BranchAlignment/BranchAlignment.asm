.armv7a
.create "output.bin",0x1000

.arm
	b 0x1002
	blx 0x1001

.thumb
	b 0x1001
	blx 0x1002

.close
