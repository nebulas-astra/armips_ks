#include "Archs/ARM/ArmElfRelocator.h"

#include "Archs/ARM/Arm.h"
#include "Core/Common.h"
#include "Parser/Parser.h"
#include "Util/Util.h"

#include <algorithm>

#include <tinyformat.h>

inline int signExtend(int value, int bitsLength)
{
	return (value << (32-bitsLength)) >> (32-bitsLength);
}

bool ArmElfRelocator::isDummyRelocationType(int type) const
{
	// R_ARM_V4BX marks the position of a bx opcode, and does not
	// cause any actual relocations
	return type == R_ARM_V4BX;
}

int ArmElfRelocator::expectedMachine() const
{
	return EM_ARM;
}

/*
	S = symbol address
	T = 1 if symbol is a thumb mode function, 0 otherwise
	P = offset of opcode
	A = addend
*/

bool ArmElfRelocator::relocateOpcode(int type, const RelocationData& data, std::vector<RelocationAction>& actions, std::vector<std::string>& errors)
{
	int t = (data.targetSymbolType == STT_FUNC && data.targetSymbolInfo != 0) ? 1 : 0;
	int p = (int) data.opcodeOffset;
	int s = (int) data.relocationBase;

	uint32_t opcode = data.opcode;
	switch (type)
	{
	case R_ARM_ABS32:		// (S + A) | T
	case R_ARM_TARGET1:
		opcode = (int) (opcode + data.relocationBase) | t;
		break;
	case R_ARM_REL32:		// ((S + A) | T) - P
		opcode = (uint32_t)(((opcode + data.relocationBase) | t) - p);
		break;
	case R_ARM_PREL31:		// (((S + A) | T) - P) & 0x7FFFFFFF
		{
			int32_t a = signExtend(opcode & 0x7FFFFFFFu, 31);
			int64_t value = (((int64_t)data.relocationBase + a) | t) - p;
			if (value < -(INT64_C(1) << 30) || value >= (INT64_C(1) << 30))
			{
				errors.emplace_back(tfm::format("Relative relocation target %08X out of range", data.relocationBase));
				return false;
			}
			opcode = (opcode & 0x80000000u) | ((uint32_t)value & 0x7FFFFFFFu);
		}
		break;
	case R_ARM_MOVW_ABS_NC:	// ((S + A) | T) & 0xFFFF
	case R_ARM_MOVT_ABS:	// ((S + A) >> 16) & 0xFFFF
		{
			int32_t a = signExtend(((opcode & 0x000F0000u) >> 4) | (opcode & 0x00000FFFu), 16);
			uint32_t value = ((uint32_t)(data.relocationBase + a)) | (uint32_t)t;
			uint32_t imm16 = (type == R_ARM_MOVT_ABS) ? ((value >> 16) & 0xFFFFu) : (value & 0xFFFFu);
			opcode = (opcode & ~0x000F0FFFu) | ((imm16 & 0xF000u) << 4) | (imm16 & 0x0FFFu);
		}
		break;
	case R_ARM_THM_MOVW_ABS_NC:	// ((S + A) | T) & 0xFFFF
	case R_ARM_THM_MOVT_ABS:	// ((S + A) >> 16) & 0xFFFF
		{
			uint32_t first = opcode & 0xFFFFu;
			uint32_t second = (opcode >> 16) & 0xFFFFu;
			int32_t a = signExtend(
				((first & 0x000Fu) << 12) |
				(((first >> 10) & 0x1u) << 11) |
				(((second >> 12) & 0x7u) << 8) |
				(second & 0x00FFu), 16);
			uint32_t value = ((uint32_t)(data.relocationBase + a)) | (uint32_t)t;
			uint32_t imm16 = (type == R_ARM_THM_MOVT_ABS) ? ((value >> 16) & 0xFFFFu) : (value & 0xFFFFu);
			first = (first & ~0x040Fu) | ((imm16 >> 12) & 0xFu) | (((imm16 >> 11) & 0x1u) << 10);
			second = (second & ~0x70FFu) | (((imm16 >> 8) & 0x7u) << 12) | (imm16 & 0xFFu);
			opcode = first | (second << 16);
		}
		break;
	case R_ARM_THM_CALL:	// ((S + A) | T) - P
	case R_ARM_THM_JUMP24:	// ((S + A) | T) - P
		{
			unsigned short first = opcode & 0xFFFF;
			unsigned short second = (opcode >> 16) & 0xFFFF;
			const bool wideThumb2 = armv7a || type == R_ARM_THM_JUMP24;

			int a;
			if (wideThumb2)
			{
				int sBit = (first >> 10) & 1;
				int j1 = (second >> 13) & 1;
				int j2 = (second >> 11) & 1;
				int i1 = ~(j1 ^ sBit) & 1;
				int i2 = ~(j2 ^ sBit) & 1;
				int opField = (sBit << 24) | (i1 << 23) | (i2 << 22) | ((first & 0x3FF) << 12) | ((second & 0x7FF) << 1);
				a = signExtend(opField, 25);
			} else {
				int opField = ((first & 0x7FF) << 11) | (second & 0x7FF);
				a = signExtend(opField << 1,23);
			}
			int value = (s+a) - p;

			first &= static_cast<unsigned short>(~0x7FFu);
			second &= static_cast<unsigned short>(wideThumb2 ? ~0x2FFFu : ~0x7FFu);

			if (t == 1)
			{
				if (data.relocationBase % 2)
				{
					errors.emplace_back("Branch target must be halfword aligned");
					return false;
				}
			} else {
				if (type == R_ARM_THM_JUMP24)
				{
					errors.emplace_back("Cannot jump from THUMB to ARM without link");
					return false;
				}

				if (arm9 == false)
				{
					errors.emplace_back("Cannot call ARM function from THUMB code without stub");
					return false;
				}

				if (data.relocationBase % 4)
				{
					errors.emplace_back("Branch target must be word aligned");
					return false;
				}
				
				value = (s + a) - (p & ~3);
				second = wideThumb2 ? 0xC000 : 0xE800;
			}

			const int limit = wideThumb2 ? 0x1000000 : 0x400000;
			if (value < -limit || value >= limit)
			{
				errors.emplace_back(tfm::format("Branch target %08X out of range",data.relocationBase));
				return false;
			}

			if (wideThumb2)
			{
				int sBit = (value >> 24) & 1;
				int i1 = (value >> 23) & 1;
				int i2 = (value >> 22) & 1;
				int j1 = ~(i1 ^ sBit) & 1;
				int j2 = ~(i2 ^ sBit) & 1;
				first |= (sBit << 10) | ((value >> 12) & 0x3FF);
				second |= (j1 << 13) | (j2 << 11) | ((value >> 1) & 0x7FF);
				if (t == 0)
					second &= ~1;
			} else {
				value >>= 1;
				first |= (value >> 11) & 0x7FF;
				second |= value & 0x7FF;
				if (t == 0)
					second &= ~1;
			}
			opcode = first | (second << 16);
		}
		break;
	case R_ARM_CALL:		// ((S + A) | T) - P
	case R_ARM_JUMP24:		// ((S + A) | T) - P
		{
			int condField = (opcode >> 28) & 0xF;
			int opField = (opcode & 0xFFFFFF) << 2;
			opcode &= ~0xFFFFFF;

			int a = signExtend(opField,26);
			int value = (s+a) - p;

			if (t == 1)
			{
				if (data.relocationBase % 2)
				{
					errors.emplace_back("Branch target must be halfword aligned");
					return false;
				}

				if (type == R_ARM_JUMP24)
				{
					errors.emplace_back("Cannot jump from ARM to THUMB without link");
					return false;
				}

				if (arm9 == false)
				{
					errors.emplace_back("Cannot call THUMB function from ARM code without stub");
					return false;
				}

				if (condField != 0xE)
				{
					errors.emplace_back("Cannot convert conditional bl into blx");
					return false;
				}

				opcode = 0xFA000000;
				if (value & 2)
					opcode |= (1 << 24);
			} else {
				if (data.relocationBase % 4)
				{
					errors.emplace_back("Branch target must be word aligned");
					return false;
				}
			}
			
			if (abs(value) >= 0x2000000)
			{
				errors.emplace_back(tfm::format("Branch target %08X out of range",data.relocationBase));
				return false;
			}

			opcode |= (value >> 2) & 0xFFFFFF;
		}
		break;
	default:
		errors.emplace_back(tfm::format("Unknown ARM relocation type %d",type));
		return false;
	}

	actions.emplace_back(data.opcodeOffset, opcode);
	return true;
}

void ArmElfRelocator::setSymbolAddress(RelocationData& data, int64_t symbolAddress, int symbolType)
{
	if (symbolType == STT_FUNC)
	{
		data.targetSymbolInfo = symbolAddress & 1;
		symbolAddress &= ~1;
	}

	data.symbolAddress = symbolAddress;
	data.targetSymbolType = symbolType;
}

const char* ctorTemplate = R"(
	push	{r4-r7,r14}
	.if %armv7a%
		movw	r4,:lower16:%ctorTable%
		movt	r4,:upper16:%ctorTable%
		movw	r5,:lower16:(%ctorTable%+%ctorTableSize%)
		movt	r5,:upper16:(%ctorTable%+%ctorTableSize%)
	.else
		ldr	r4,=%ctorTable%
		ldr	r5,=%ctorTable%+%ctorTableSize%
	.endif
	%outerLoopLabel%:
	ldr	r6,[r4]
	ldr	r7,[r4,#4]
	add	r4,#8
	%innerLoopLabel%:
	ldr	r0,[r6]
	add	r6,#4
	.if %simpleMode%
		blx	r0
	.else
		bl	%stubName%
	.endif
	cmp	r6,r7
	blt	%innerLoopLabel%
	cmp	r4,r5
	blt	%outerLoopLabel%
	.if %simpleMode%
		pop	{r4-r7,r15}
	.else
		pop	{r4-r7}
		pop	{r0}
		%stubName%:
		bx	r0
	.endif
	.if !%armv7a%
		.pool
	.endif
	%ctorTable%:
	.word %ctorContent%
)";

std::unique_ptr<CAssemblerCommand> ArmElfRelocator::generateCtorStub(std::vector<ElfRelocatorCtor>& ctors)
{
	Parser parser;
	if (ctors.size() != 0)
	{
		bool simpleMode = arm9 == false && Arm.GetThumbMode();

		// create constructor table
		std::string table;
		for (size_t i = 0; i < ctors.size(); i++)
		{
			if (i != 0)
				table += ',';
			table += tfm::format("%s,%s+0x%08X",ctors[i].symbolName,ctors[i].symbolName,ctors[i].size);
		}

		return parser.parseTemplate(ctorTemplate,{
			{ "%ctorTable%",		Global.symbolTable.getUniqueLabelName().string() },
			{ "%ctorTableSize%",	tfm::format("%d",ctors.size()*8) },
			{ "%outerLoopLabel%",	Global.symbolTable.getUniqueLabelName().string() },
			{ "%innerLoopLabel%",	Global.symbolTable.getUniqueLabelName().string() },
			{ "%stubName%",		Global.symbolTable.getUniqueLabelName().string() },
			{ "%simpleMode%",		simpleMode ? "1" : "0" },
			{ "%armv7a%",		armv7a ? "1" : "0" },
			{ "%ctorContent%",		table },
		});
	} else {
		return parser.parseTemplate("bx r14");
	}
}
