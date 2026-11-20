#pragma once

#include "Core/ELF/ElfRelocator.h"

enum {
	R_ARM_ABS32 = 2,
	R_ARM_REL32 = 3,
	R_ARM_THM_CALL = 10,
	R_ARM_CALL = 28,
	R_ARM_JUMP24 = 29,
	R_ARM_THM_JUMP24 = 30,
	R_ARM_TARGET1 = 38,
	R_ARM_V4BX = 40,
	R_ARM_PREL31 = 42,
	R_ARM_MOVW_ABS_NC = 43,
	R_ARM_MOVT_ABS = 44,
	R_ARM_THM_MOVW_ABS_NC = 47,
	R_ARM_THM_MOVT_ABS = 48,
};


class ArmElfRelocator: public IElfRelocator
{
public:
	ArmElfRelocator(bool arm9, bool armv7a = false): arm9(arm9), armv7a(armv7a) { }
	int expectedMachine() const override;
	bool isDummyRelocationType(int type) const override;

	bool relocateOpcode(int type, const RelocationData& data, std::vector<RelocationAction>& actions, std::vector<std::string>& errors) override;
	void setSymbolAddress(RelocationData& data, int64_t symbolAddress, int symbolType) override;

	std::unique_ptr<CAssemblerCommand> generateCtorStub(std::vector<ElfRelocatorCtor>& ctors) override;
private:
	bool arm9;
	bool armv7a;
};
