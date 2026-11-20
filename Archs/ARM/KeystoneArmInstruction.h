#pragma once

#include "Archs/ARM/Arm.h"
#include "Core/Expression.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

// A structured piece of an ARMv7-A / Thumb-2 statement. Architectural tokens
// (registers, shifts, condition codes, punctuation) are kept separate from
// armips expressions so every immediate, offset, and branch target is evaluated
// by armips' own expression engine on each validation pass before reaching Keystone.
struct KeystoneStatementPart
{
	enum class Kind
	{
		Mnemonic,
		Keyword,
		Punct,
		Expression,
		AmbiguousRegOrExpr,
	};

	enum class RelocModifier
	{
		None,
		Lower16,
		Upper16,
	};

	Kind kind = Kind::Punct;
	RelocModifier reloc = RelocModifier::None;
	std::string text;
	Expression expression;
	bool hasSymbolOrFunc = false;
};

class CKeystoneArmInstruction: public ArmOpcodeCommand
{
public:
	CKeystoneArmInstruction(std::vector<KeystoneStatementPart> parts, std::string source,
		std::string mnemonic, bool thumb, Endianness endianness, bool pcRelAddSub = false);

	bool Validate(const ValidateState& state) override;
	void Encode() const override;
	void writeTempData(TempData& tempData) const override;
	void setPoolAddress(int64_t address) override { }

private:
	static bool resolveSymbol(const char* symbol, uint64_t* value);
	bool resolveSymbolForCommand(const char* symbol, uint64_t* value);
	bool buildSource(std::string& rendered, bool& hasEvalError, bool& hasBranchTarget,
		int64_t& branchTarget, bool forceWide);

	std::vector<KeystoneStatementPart> parts;
	std::string source;
	std::string mnemonic;
	bool thumb;
	Endianness endianness;
	bool pcRelAddSub;
	std::vector<unsigned char> encoding;
	int64_t address = 0;
	size_t lastAdvanceSize = 0;
	int widenCount = 0;
	bool lockedWide = false;

	static thread_local CKeystoneArmInstruction* activeCommand;
};

std::unique_ptr<CAssemblerCommand> parseKeystoneArmOpcode(
	Parser& parser, bool thumb, Endianness endianness);
void resetKeystoneItValidationState();
void flushIncompleteKeystoneItBlock();
