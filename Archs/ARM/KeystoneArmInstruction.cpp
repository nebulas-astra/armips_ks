#include "Archs/ARM/KeystoneArmInstruction.h"
#include "Archs/ARM/ArmParser.h"

#ifdef ARMIPS_HAS_KEYSTONE

#include "Core/Common.h"
#include "Core/ExpressionFunctionHandler.h"
#include "Core/FileManager.h"
#include "Core/Misc.h"
#include "Parser/Parser.h"
#include "Util/Util.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <keystone/keystone.h>
#include <sstream>
#include <string_view>
#include <tinyformat.h>
#include <utility>

namespace
{
	struct KeystoneEngines
	{
		std::array<ks_engine*, 4> handles{};
	};

	KeystoneEngines& engines()
	{
		// Keystone warns that closing one handle can invalidate process-wide
		// caches used by other handles. Keep these four handles for process life.
		static auto* value = new KeystoneEngines();
		return *value;
	}

	size_t engineIndex(bool thumb, Endianness endianness)
	{
		return (thumb ? 1u : 0u) | (endianness == Endianness::Big ? 2u : 0u);
	}

	struct ActiveItValidationState
	{
		bool active = false;
		bool valid = false;
		CKeystoneArmInstruction* opener = nullptr;
		size_t expectedStatementCount = 0;
		int64_t startAddress = 0;
		size_t encodedPrefixSize = 0;
		Endianness endianness = Endianness::Little;
		std::vector<std::string> renderedStatements;

		void reset()
		{
			active = false;
			valid = false;
			opener = nullptr;
			expectedStatementCount = 0;
			startAddress = 0;
			encodedPrefixSize = 0;
			endianness = Endianness::Little;
			renderedStatements.clear();
		}
	};

	ActiveItValidationState activeItState;

	bool isConditionCode(std::string_view text)
	{
		static constexpr std::array<std::string_view, 17> codes = {{
			"eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl",
			"vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al",
		}};
		return std::find(codes.begin(), codes.end(), text) != codes.end();
	}

	bool hasWidthSuffix(std::string_view mnemonic)
	{
		if (mnemonic.size() < 3)
			return false;
		const std::string_view suffix = mnemonic.substr(mnemonic.size() - 2);
		return suffix == ".w" || suffix == ".n";
	}

	std::string_view stripWidthSuffix(std::string_view mnemonic)
	{
		if (hasWidthSuffix(mnemonic))
			return mnemonic.substr(0, mnemonic.size() - 2);
		return mnemonic;
	}

	size_t getItExpectedStatementCount(std::string_view mnemonic)
	{
		std::string_view base = mnemonic;
		if (base.size() >= 4 && base.substr(base.size() - 2) == ".n")
			base = base.substr(0, base.size() - 2);

		if (base.size() < 2 || base.size() > 5 || base[0] != 'i' || base[1] != 't')
			return 0;

		if (!std::all_of(base.begin() + 2, base.end(), [](char value) {
			return value == 't' || value == 'e';
		}))
		{
			return 0;
		}

		return base.size();
	}

	bool isItMnemonic(std::string_view mnemonic)
	{
		return getItExpectedStatementCount(mnemonic) != 0;
	}

	bool isMovwMnemonic(std::string_view mnemonic)
	{
		const std::string_view base = stripWidthSuffix(mnemonic);
		if (base == "movw")
			return true;
		return base.size() == 6 && base.substr(0, 4) == "movw" && isConditionCode(base.substr(4));
	}

	bool isMovtMnemonic(std::string_view mnemonic)
	{
		const std::string_view base = stripWidthSuffix(mnemonic);
		if (base == "movt")
			return true;
		return base.size() == 6 && base.substr(0, 4) == "movt" && isConditionCode(base.substr(4));
	}

	bool isAdrMnemonic(std::string_view mnemonic)
	{
		const std::string_view base = stripWidthSuffix(mnemonic);
		if (base == "adr")
			return true;
		return base.size() == 5 && base.substr(0, 3) == "adr" && isConditionCode(base.substr(3));
	}

	struct BranchKind
	{
		bool isBranch = false;
		bool isBl = false;
		bool isBlx = false;
		bool isCbz = false;
	};

	BranchKind classifyBranchMnemonic(std::string_view mnemonic)
	{
		BranchKind kind;
		const std::string_view base = stripWidthSuffix(mnemonic);

		if (base == "cbz" || base == "cbnz")
		{
			kind.isBranch = true;
			kind.isCbz = true;
			return kind;
		}

		if (base == "blx" || (base.size() == 5 && base.substr(0, 3) == "blx" && isConditionCode(base.substr(3))))
		{
			kind.isBranch = true;
			kind.isBlx = true;
			return kind;
		}

		if (base == "bl" || (base.size() == 4 && base.substr(0, 2) == "bl" && isConditionCode(base.substr(2))))
		{
			kind.isBranch = true;
			kind.isBl = true;
			return kind;
		}

		if (base == "b" || (base.size() == 3 && base[0] == 'b' && isConditionCode(base.substr(1))))
		{
			kind.isBranch = true;
			return kind;
		}

		return kind;
	}

	bool isLoadMnemonic(std::string_view mnemonic)
	{
		return mnemonic.rfind("ldr", 0) == 0 || mnemonic.rfind("vldr", 0) == 0;
	}

	bool isAddOrSubPcRelMnemonic(std::string_view mnemonic)
	{
		const std::string_view base = stripWidthSuffix(mnemonic);
		if (base.size() < 3)
			return false;
		const std::string_view prefix = base.substr(0, 3);
		if (prefix != "add" && prefix != "sub")
			return false;
		if (base.size() == 3)
			return true;
		return base.size() == 5 && isConditionCode(base.substr(3));
	}

	bool isVfpOrNeonMnemonic(std::string_view mnemonic)
	{
		return !mnemonic.empty() && (mnemonic[0] == 'v' || mnemonic[0] == 'f');
	}

	bool isCoprocessorMnemonic(std::string_view mnemonic)
	{
		return mnemonic.rfind("cdp", 0) == 0 ||
			mnemonic.rfind("ldc", 0) == 0 ||
			mnemonic.rfind("stc", 0) == 0 ||
			mnemonic.rfind("mcr", 0) == 0 ||
			mnemonic.rfind("mrc", 0) == 0;
	}

	bool isSysRegMnemonic(std::string_view mnemonic)
	{
		const std::string_view base = stripWidthSuffix(mnemonic);
		return base.rfind("mrs", 0) == 0 ||
			base.rfind("msr", 0) == 0 ||
			base.rfind("vmrs", 0) == 0 ||
			base.rfind("vmsr", 0) == 0 ||
			base.rfind("fmrx", 0) == 0 ||
			base.rfind("fmxr", 0) == 0;
	}

	bool isBarrierMnemonic(std::string_view mnemonic)
	{
		const std::string_view base = stripWidthSuffix(mnemonic);
		return base == "dmb" || base == "dsb" || base == "isb";
	}

	bool isCpsMnemonic(std::string_view mnemonic)
	{
		const std::string_view base = stripWidthSuffix(mnemonic);
		return base == "cps" || base == "cpsie" || base == "cpsid";
	}

	bool isSetendMnemonic(std::string_view mnemonic)
	{
		return mnemonic == "setend";
	}

	bool isThumbNarrowAluMnemonic(std::string_view mnemonic)
	{
		static constexpr std::array<std::string_view, 17> mnemonics = {{
			"mov", "add", "sub", "lsl", "lsr", "asr", "ror",
			"and", "eor", "orr", "bic", "mvn", "mul", "adc", "sbc", "rsb", "neg",
		}};
		return std::find(mnemonics.begin(), mnemonics.end(), mnemonic) != mnemonics.end();
	}

	bool isPrefixedNumberInRange(std::string_view text, char prefix, int maxValue)
	{
		if (text.size() < 2 || text.size() > 3 || text[0] != prefix)
			return false;
		if (text.size() == 3 && text[1] == '0')
			return false;

		int value = 0;
		for (size_t i = 1; i < text.size(); ++i)
		{
			if (text[i] < '0' || text[i] > '9')
				return false;
			value = value * 10 + (text[i] - '0');
		}
		return value <= maxValue;
	}

	bool isCoreGpr(std::string_view text)
	{
		return text == "sp" || text == "lr" || text == "pc" ||
			isPrefixedNumberInRange(text, 'r', 15);
	}

	bool isAapcsPrimaryAlias(std::string_view text)
	{
		return text == "ip" || text == "fp";
	}

	bool isAapcsSecondaryAlias(std::string_view text)
	{
		static constexpr std::array<std::string_view, 15> aliases = {{
			"sl", "sb", "wr",
			"a1", "a2", "a3", "a4",
			"v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8",
		}};
		return std::find(aliases.begin(), aliases.end(), text) != aliases.end();
	}

	bool isAnyGprName(std::string_view text)
	{
		return isCoreGpr(text) || isAapcsPrimaryAlias(text) || isAapcsSecondaryAlias(text);
	}

	bool isVfpRegister(std::string_view text)
	{
		return isPrefixedNumberInRange(text, 's', 31) ||
			isPrefixedNumberInRange(text, 'd', 31) ||
			isPrefixedNumberInRange(text, 'q', 15);
	}

	bool isCoprocessorName(std::string_view text)
	{
		return isPrefixedNumberInRange(text, 'p', 15) ||
			isPrefixedNumberInRange(text, 'c', 15);
	}

	bool isShiftKeyword(std::string_view text)
	{
		return text == "lsl" || text == "lsr" || text == "asr" ||
			text == "ror" || text == "rrx" || text == "asl";
	}

	bool isBarrierOption(std::string_view text)
	{
		static constexpr std::array<std::string_view, 12> options = {{
			"sy", "st", "ld",
			"ish", "ishst", "ishld",
			"nsh", "nshst", "nshld",
			"osh", "oshst", "oshld",
		}};
		return std::find(options.begin(), options.end(), text) != options.end();
	}

	bool isCpsFlags(std::string_view text)
	{
		if (text.empty() || text.size() > 3)
			return false;
		bool seenA = false;
		bool seenI = false;
		bool seenF = false;
		for (char ch : text)
		{
			if (ch == 'a' && !seenA)
				seenA = true;
			else if (ch == 'i' && !seenI)
				seenI = true;
			else if (ch == 'f' && !seenF)
				seenF = true;
			else
				return false;
		}
		return true;
	}

	bool isSetendOption(std::string_view text)
	{
		return text == "le" || text == "be";
	}

	bool isSysRegKeyword(std::string_view text)
	{
		if (text.rfind("cpsr", 0) == 0 || text.rfind("spsr", 0) == 0 || text.rfind("apsr", 0) == 0)
			return true;

		static constexpr std::array<std::string_view, 16> names = {{
			"fpscr", "fpexc", "fpsid", "mvfr0", "mvfr1", "mvfr2", "fpinst", "fpinst2",
			"primask", "basepri", "basepri_max", "faultmask", "control",
			"ipsr", "epsr", "iepsr",
		}};
		if (std::find(names.begin(), names.end(), text) != names.end())
			return true;

		static constexpr std::array<std::string_view, 6> extraNames = {{
			"iapsr", "eapsr", "xpsr", "msp", "psp", "elr_hyp",
		}};
		if (std::find(extraNames.begin(), extraNames.end(), text) != extraNames.end())
			return true;

		static constexpr std::array<std::string_view, 8> bankedSuffixes = {{
			"_usr", "_fiq", "_irq", "_svc", "_abt", "_und", "_mon", "_hyp",
		}};
		for (std::string_view suffix : bankedSuffixes)
		{
			if (text.size() > suffix.size() &&
				text.substr(text.size() - suffix.size()) == suffix)
				return true;
		}
		return false;
	}

	bool isBinaryExpressionOperator(TokenType type)
	{
		switch (type)
		{
		case TokenType::Plus:
		case TokenType::Minus:
		case TokenType::Mult:
		case TokenType::Div:
		case TokenType::Mod:
		case TokenType::Caret:
		case TokenType::LeftShift:
		case TokenType::RightShift:
		case TokenType::Less:
		case TokenType::Greater:
		case TokenType::LessEqual:
		case TokenType::GreaterEqual:
		case TokenType::Equal:
		case TokenType::NotEqual:
		case TokenType::BitAnd:
		case TokenType::BitOr:
		case TokenType::LogAnd:
		case TokenType::LogOr:
		case TokenType::Question:
			return true;
		default:
			return false;
		}
	}

	std::string formatKeystoneInteger(int64_t value)
	{
		std::ostringstream stream;
		if (value < 0)
		{
			stream << "-0x" << std::hex << (uint64_t{0} - static_cast<uint64_t>(value));
		}
		else
		{
			stream << "0x" << std::hex << static_cast<uint64_t>(value);
		}
		return stream.str();
	}

	std::string formatKeystoneFloat(double value)
	{
		// Configuring Keystone's symbol resolver switches its lexer to radix 16,
		// which makes decimal floating point literals such as "1.0" invalid.
		// C99 hexadecimal literals (e.g. "0x1.8p+1") are accepted both with and
		// without the resolver and keep the exact value.
		char buffer[64];
		std::snprintf(buffer, sizeof(buffer), "%a", value);
		return buffer;
	}

	int64_t normalizeImmediateTo32Bit(int64_t value)
	{
		if (value > INT64_C(0xFFFFFFFF))
			return static_cast<int64_t>(static_cast<uint32_t>(value));
		if (value < -INT64_C(0x80000000))
			return static_cast<int64_t>(static_cast<int32_t>(static_cast<uint32_t>(value)));
		return value;
	}

	std::string tokenText(const Token& token)
	{
		if (token.type == TokenType::Identifier)
			return token.identifierValue().string();
		if (token.type == TokenType::Integer)
			return formatKeystoneInteger(token.intValue());
		return token.getOriginalText();
	}

	bool needsSpaceBefore(KeystoneStatementPart::Kind prevKind, std::string_view prevText,
		KeystoneStatementPart::Kind curKind, std::string_view curText)
	{
		if (prevKind == KeystoneStatementPart::Kind::Mnemonic)
			return true;

		if (prevKind == KeystoneStatementPart::Kind::Punct)
		{
			if (prevText == ",")
				return true;
			if (prevText == "[" || prevText == "{" || prevText == "#" ||
				prevText == ":" || prevText == "-" || prevText == "+")
				return false;
			if (prevText == "]" || prevText == "}" || prevText == "!" || prevText == "^")
				return curKind != KeystoneStatementPart::Kind::Punct;
		}

		if (curKind == KeystoneStatementPart::Kind::Punct)
		{
			if (curText == "," || curText == "]" || curText == "}" ||
				curText == "!" || curText == "^" || curText == ":" || curText == "-")
				return false;
			if (curText == "[")
				return prevKind != KeystoneStatementPart::Kind::Keyword;
			return true;
		}

		return true;
	}

	struct ParsedStatement
	{
		std::string text;
		std::string mnemonic;
		std::vector<KeystoneStatementPart> parts;
		bool hasLiteralPoolSyntax = false;
		bool hasParseError = false;
		bool pcRelAddSub = false;
	};

	bool parseExpressionPart(Parser& parser, KeystoneStatementPart::RelocModifier reloc,
		KeystoneStatementPart& outPart, std::string& outRawText)
	{
		const TokenizerPosition start = parser.getTokenizer()->getPosition();
		Expression expression = parser.parseExpression();
		const TokenizerPosition end = parser.getTokenizer()->getPosition();
		if (!expression.isLoaded())
			return false;

		std::string rawText;
		bool hasSymbolOrFunc = false;
		for (const Token& tokenPart : parser.getTokenizer()->getTokens(start, end))
		{
			if (tokenPart.type == TokenType::Identifier)
				hasSymbolOrFunc = true;
			if (!rawText.empty())
				rawText += ' ';
			rawText += tokenText(tokenPart);
		}

		outPart.kind = KeystoneStatementPart::Kind::Expression;
		outPart.reloc = reloc;
		outPart.text = rawText;
		outPart.expression = std::move(expression);
		outPart.hasSymbolOrFunc = hasSymbolOrFunc;
		outRawText = std::move(rawText);
		return true;
	}

	void appendSourceToken(std::string& dest, std::string_view piece)
	{
		if (piece.empty())
			return;
		if (!dest.empty())
			dest += ' ';
		dest.append(piece.data(), piece.size());
	}

	ParsedStatement readStatement(Parser& parser)
	{
		ParsedStatement result;

		const Token mnemonicToken = parser.nextToken();
		result.mnemonic = mnemonicToken.identifierValue().string();
		result.text = result.mnemonic;

		KeystoneStatementPart mnemonicPart;
		mnemonicPart.kind = KeystoneStatementPart::Kind::Mnemonic;
		mnemonicPart.text = result.mnemonic;
		result.parts.push_back(std::move(mnemonicPart));

		const BranchKind branchKind = classifyBranchMnemonic(result.mnemonic);
		const bool isIt = isItMnemonic(result.mnemonic);
		const bool isMovw = isMovwMnemonic(result.mnemonic);
		const bool isMovt = isMovtMnemonic(result.mnemonic);
		const bool isAdr = isAdrMnemonic(result.mnemonic);
		const bool isLoad = isLoadMnemonic(result.mnemonic);
		const bool isAddSubPcRel = isAddOrSubPcRelMnemonic(result.mnemonic);
		const bool isVfp = isVfpOrNeonMnemonic(result.mnemonic);
		const bool isCoproc = isCoprocessorMnemonic(result.mnemonic);
		const bool isSysReg = isSysRegMnemonic(result.mnemonic);
		const bool isBarrier = isBarrierMnemonic(result.mnemonic);
		const bool isCps = isCpsMnemonic(result.mnemonic);
		const bool isSetend = isSetendMnemonic(result.mnemonic);

		int braceDepth = 0;
		int bracketDepth = 0;
		int commaCount = 0;
		bool afterHash = false;
		bool afterComma = false;
		bool afterLBrack = false;
		bool prevOperandWasRegister = false;

		while (!parser.atEnd() && parser.peekToken().type != TokenType::Separator)
		{
			const Token token = parser.peekToken();

			if (token.type == TokenType::Invalid)
			{
				parser.printError(token, "Invalid token '%s'", token.getOriginalText());
				result.hasParseError = true;
				return result;
			}

			// Handle '=': reject literal-pool loads, translate native armips add/sub Rd, =Expr.
			if (token.type == TokenType::Assign)
			{
				if (isAddSubPcRel && bracketDepth == 0 && braceDepth == 0 &&
					commaCount == 1 && afterComma && result.parts.size() == 3 &&
					result.parts[1].kind == KeystoneStatementPart::Kind::Keyword)
				{
					parser.eatToken(); // '='
					appendSourceToken(result.text, "=");
					if (parser.peekToken().type == TokenType::Hash)
					{
						parser.eatToken();
						appendSourceToken(result.text, "#");
					}

					KeystoneStatementPart exprPart;
					std::string rawText;
					if (!parseExpressionPart(parser, KeystoneStatementPart::RelocModifier::None, exprPart, rawText))
					{
						parser.printError(token, "Invalid expression after '='");
						result.hasParseError = true;
						return result;
					}
					if (!parser.atEnd() && parser.peekToken().type != TokenType::Separator)
					{
						parser.printError(parser.peekToken(), "Unexpected token after '=' expression");
						result.hasParseError = true;
						return result;
					}
					appendSourceToken(result.text, rawText);
					result.parts.push_back(std::move(exprPart));
					result.pcRelAddSub = true;
					afterComma = false;
					afterHash = false;
					afterLBrack = false;
					prevOperandWasRegister = false;
					continue;
				}

				if (isLoad)
				{
					result.hasLiteralPoolSyntax = true;
					while (!parser.atEnd() && parser.peekToken().type != TokenType::Separator)
						parser.eatToken();
					return result;
				}

				parser.printError(token, "Unexpected '=' in ARMv7-A instruction");
				result.hasParseError = true;
				return result;
			}

			// Handle :lower16:expr and :upper16:expr natively.
			if (token.type == TokenType::Colon &&
				parser.peekToken(1).type == TokenType::Identifier &&
				parser.peekToken(2).type == TokenType::Colon)
			{
				const std::string& modName = parser.peekToken(1).identifierValue().string();
				if (modName == "lower16" || modName == "upper16")
				{
					const auto modifier = (modName == "lower16")
						? KeystoneStatementPart::RelocModifier::Lower16
						: KeystoneStatementPart::RelocModifier::Upper16;
					parser.eatTokens(3);

					KeystoneStatementPart exprPart;
					std::string rawText;
					if (!parseExpressionPart(parser, modifier, exprPart, rawText))
					{
						parser.printError(token, "Invalid expression after :%s:", modName);
						result.hasParseError = true;
						return result;
					}

					appendSourceToken(result.text, ":" + modName + ":" + rawText);
					result.parts.push_back(std::move(exprPart));
					afterHash = false;
					afterComma = false;
					afterLBrack = false;
					prevOperandWasRegister = false;
					continue;
				}
			}

			// Handle '!' (writeback suffix vs unary logical NOT in expression).
			if (token.type == TokenType::Exclamation)
			{
				const auto& prev = result.parts.back();
				const bool isWriteback =
					prev.kind == KeystoneStatementPart::Kind::Keyword ||
					(prev.kind == KeystoneStatementPart::Kind::Punct && prev.text == "]");
				if (isWriteback)
				{
					parser.eatToken();
					KeystoneStatementPart part;
					part.kind = KeystoneStatementPart::Kind::Punct;
					part.text = "!";
					result.parts.push_back(std::move(part));
					appendSourceToken(result.text, "!");
					afterComma = false;
					afterHash = false;
					afterLBrack = false;
					continue;
				}
			}

			// Handle '^' (LDM/STM user-mode suffix after '}' vs bitwise XOR in expression).
			if (token.type == TokenType::Caret)
			{
				const auto& prev = result.parts.back();
				if (prev.kind == KeystoneStatementPart::Kind::Punct && prev.text == "}")
				{
					parser.eatToken();
					KeystoneStatementPart part;
					part.kind = KeystoneStatementPart::Kind::Punct;
					part.text = "^";
					result.parts.push_back(std::move(part));
					appendSourceToken(result.text, "^");
					afterComma = false;
					afterHash = false;
					afterLBrack = false;
					continue;
				}
			}

			// Structural punctuation tokens.
			if (token.type == TokenType::Comma ||
				token.type == TokenType::LBrack || token.type == TokenType::RBrack ||
				token.type == TokenType::LBrace || token.type == TokenType::RBrace ||
				token.type == TokenType::Hash || token.type == TokenType::Colon)
			{
				const Token consumed = parser.nextToken();
				KeystoneStatementPart part;
				part.kind = KeystoneStatementPart::Kind::Punct;
				part.text = consumed.getOriginalText();
				result.parts.push_back(std::move(part));
				appendSourceToken(result.text, consumed.getOriginalText());

				switch (consumed.type)
				{
				case TokenType::Comma:
					if (braceDepth == 0 && bracketDepth == 0)
						commaCount++;
					afterComma = true;
					afterHash = false;
					afterLBrack = false;
					break;
				case TokenType::LBrack:
					bracketDepth++;
					afterLBrack = true;
					afterComma = false;
					afterHash = false;
					prevOperandWasRegister = false;
					break;
				case TokenType::RBrack:
					if (bracketDepth > 0)
						bracketDepth--;
					afterLBrack = false;
					afterComma = false;
					afterHash = false;
					prevOperandWasRegister = false;
					break;
				case TokenType::LBrace:
					braceDepth++;
					afterComma = false;
					afterHash = false;
					afterLBrack = false;
					prevOperandWasRegister = false;
					break;
				case TokenType::RBrace:
					if (braceDepth > 0)
						braceDepth--;
					afterComma = false;
					afterHash = false;
					afterLBrack = false;
					prevOperandWasRegister = false;
					break;
				case TokenType::Hash:
					afterHash = true;
					afterComma = false;
					afterLBrack = false;
					prevOperandWasRegister = false;
					break;
				case TokenType::Colon:
					afterComma = false;
					afterHash = false;
					afterLBrack = false;
					prevOperandWasRegister = false;
					break;
				default:
					break;
				}
				continue;
			}

			// Register-range '-' inside '{...}' and signed index register [r0, -r1] / [r0], -r1.
			if (token.type == TokenType::Minus || token.type == TokenType::Plus)
			{
				const bool isRangeDash = (token.type == TokenType::Minus) &&
					braceDepth > 0 &&
					result.parts.back().kind == KeystoneStatementPart::Kind::Keyword;

				bool isSignedRegister = false;
				if (!afterHash && (bracketDepth > 0 || afterComma) &&
					parser.peekToken(1).type == TokenType::Identifier)
				{
					const std::string& nextId = parser.peekToken(1).identifierValue().string();
					const TokenType afterReg = parser.peekToken(2).type;
					if (isAnyGprName(nextId) &&
						(afterReg == TokenType::Comma || afterReg == TokenType::RBrack ||
						 afterReg == TokenType::Separator || afterReg == TokenType::Invalid))
					{
						isSignedRegister = true;
					}
				}

				if (isRangeDash || isSignedRegister)
				{
					const Token consumed = parser.nextToken();
					KeystoneStatementPart part;
					part.kind = KeystoneStatementPart::Kind::Punct;
					part.text = consumed.getOriginalText();
					result.parts.push_back(std::move(part));
					appendSourceToken(result.text, consumed.getOriginalText());
					afterComma = false;
					afterHash = false;
					afterLBrack = false;
					continue;
				}
			}

			// Contextual architectural keywords (registers, shifts, barriers, condition codes).
			if (token.type == TokenType::Identifier)
			{
				const std::string& id = token.identifierValue().string();
				const TokenType nextType = parser.peekToken(1).type;
				const bool isFuncCall = nextType == TokenType::LParen &&
					ExpressionFunctionHandler::instance().find(token.identifierValue()).has_value();
				const bool isExprStartByOp = braceDepth == 0 && isBinaryExpressionOperator(nextType);
				const bool inPureExprSlot =
					(branchKind.isBranch && !branchKind.isBlx && !branchKind.isCbz) ||
					(branchKind.isCbz && commaCount >= 1) ||
					(isAdr && commaCount >= 1) ||
					((isMovw || isMovt) && commaCount >= 1);

				if (!afterHash && !isFuncCall && !isExprStartByOp && !inPureExprSlot)
				{
					bool isKeyword = false;
					bool isRegKeyword = false;
					bool isAmbiguousAlias = false;

					if (isIt && commaCount == 0 && isConditionCode(id))
						isKeyword = true;
					else if (isBarrier && isBarrierOption(id))
						isKeyword = true;
					else if (isCps && isCpsFlags(id))
						isKeyword = true;
					else if (isSetend && isSetendOption(id))
						isKeyword = true;
					else if (isSysReg && isSysRegKeyword(id))
					{
						isKeyword = true;
						isRegKeyword = true;
					}
					else if (isVfp && isVfpRegister(id))
					{
						isKeyword = true;
						isRegKeyword = true;
					}
					else if (isCoproc && isCoprocessorName(id))
					{
						isKeyword = true;
						isRegKeyword = true;
					}
					else if (afterComma && isShiftKeyword(id))
					{
						if (id == "rrx")
							isKeyword = prevOperandWasRegister;
						else
							isKeyword = nextType != TokenType::Separator &&
								nextType != TokenType::RBrack &&
								nextType != TokenType::Comma;
					}
					else if (isCoreGpr(id) || isAapcsPrimaryAlias(id))
					{
						isKeyword = true;
						isRegKeyword = true;
					}
					else if (isAapcsSecondaryAlias(id))
					{
						if (braceDepth > 0 || afterLBrack || (!branchKind.isBranch && commaCount == 0 && bracketDepth == 0))
						{
							isKeyword = true;
							isRegKeyword = true;
						}
						else if (!branchKind.isBlx)
						{
							isAmbiguousAlias = true;
						}
					}

					if (isKeyword)
					{
						parser.eatToken();
						KeystoneStatementPart part;
						part.kind = KeystoneStatementPart::Kind::Keyword;
						part.text = id;
						result.parts.push_back(std::move(part));
						appendSourceToken(result.text, id);
						afterComma = false;
						afterHash = false;
						afterLBrack = false;
						prevOperandWasRegister = isRegKeyword;
						continue;
					}

					if (isAmbiguousAlias)
					{
						KeystoneStatementPart exprPart;
						std::string rawText;
						if (!parseExpressionPart(parser, KeystoneStatementPart::RelocModifier::None, exprPart, rawText))
						{
							parser.printError(token, "Invalid operand '%s'", token.getOriginalText());
							result.hasParseError = true;
							return result;
						}
						exprPart.kind = KeystoneStatementPart::Kind::AmbiguousRegOrExpr;
						exprPart.text = id;
						result.parts.push_back(std::move(exprPart));
						appendSourceToken(result.text, id);
						afterComma = false;
						afterHash = false;
						afterLBrack = false;
						prevOperandWasRegister = true;
						continue;
					}
				}
			}

			// Everything else in an operand slot is an armips expression.
			KeystoneStatementPart exprPart;
			std::string rawText;
			if (!parseExpressionPart(parser, KeystoneStatementPart::RelocModifier::None, exprPart, rawText))
			{
				parser.printError(token, "Invalid expression in ARMv7-A operand");
				result.hasParseError = true;
				return result;
			}

			appendSourceToken(result.text, rawText);
			result.parts.push_back(std::move(exprPart));
			afterHash = false;
			afterComma = false;
			afterLBrack = false;
			prevOperandWasRegister = false;
		}

		return result;
	}

	// Keystone only accepts explicit width suffixes on Thumb instructions that
	// have both 16-bit and 32-bit encodings. BL and BLX (immediate) are
	// 32-bit-only and IT is 16-bit-only in Thumb, so GNU-style spellings like
	// "bl.w", "bleq.w", "blx.w", and "it.n" -- which disassemblers emit -- can
	// be rejected. Keep "blx.w <reg>" untouched so invalid 32-bit register BLX
	// is still rejected.
	void removeRedundantWidthSuffix(ParsedStatement& statement)
	{
		if (statement.mnemonic.size() < 4)
			return;

		const std::string_view suffix = std::string_view(statement.mnemonic)
			.substr(statement.mnemonic.size() - 2);
		const std::string_view base = std::string_view(statement.mnemonic)
			.substr(0, statement.mnemonic.size() - 2);

		if (suffix == ".n" && isItMnemonic(base))
		{
			const std::string stripped(base);
			statement.text.replace(0, statement.mnemonic.size(), stripped);
			statement.mnemonic = stripped;
			if (!statement.parts.empty() &&
				statement.parts.front().kind == KeystoneStatementPart::Kind::Mnemonic)
				statement.parts.front().text = stripped;
			return;
		}

		if (suffix != ".w")
			return;

		const bool isBl = base == "bl" ||
			(base.size() == 4 && base.substr(0, 2) == "bl" && isConditionCode(base.substr(2)));
		const bool isBlx = base == "blx" ||
			(base.size() == 5 && base.substr(0, 3) == "blx" && isConditionCode(base.substr(3)));

		if (!isBl && !isBlx)
			return;

		if (isBlx && statement.parts.size() >= 2 &&
			statement.parts[1].kind == KeystoneStatementPart::Kind::Keyword)
			return;

		const std::string stripped(base);
		statement.text.replace(0, statement.mnemonic.size(), stripped);
		statement.mnemonic = stripped;
		if (!statement.parts.empty() &&
			statement.parts.front().kind == KeystoneStatementPart::Kind::Mnemonic)
			statement.parts.front().text = stripped;
	}

	ks_engine* getEngine(bool thumb, Endianness endianness)
	{
		ks_engine*& engine = engines().handles[engineIndex(thumb, endianness)];
		if (engine != nullptr)
			return engine;

		int mode = thumb ? KS_MODE_THUMB : KS_MODE_ARM;
		if (endianness == Endianness::Big)
			mode |= KS_MODE_BIG_ENDIAN;

		if (ks_open(KS_ARCH_ARM, mode, &engine) != KS_ERR_OK)
		{
			engine = nullptr;
			return nullptr;
		}

		if (ks_option(engine, KS_OPT_SYM_RESOLVER,
				reinterpret_cast<size_t>(&CKeystoneArmInstruction::resolveSymbol)) != KS_ERR_OK)
		{
			engine = nullptr;
			return nullptr;
		}
		return engine;
	}
}

thread_local CKeystoneArmInstruction* CKeystoneArmInstruction::activeCommand = nullptr;

CKeystoneArmInstruction::CKeystoneArmInstruction(std::vector<KeystoneStatementPart> parts,
	std::string source, std::string mnemonic, bool thumb, Endianness endianness, bool pcRelAddSub)
	: parts(std::move(parts)), source(std::move(source)), mnemonic(std::move(mnemonic)),
	  thumb(thumb), endianness(endianness), pcRelAddSub(pcRelAddSub)
{
}

bool CKeystoneArmInstruction::resolveSymbol(const char* symbol, uint64_t* value)
{
	return activeCommand != nullptr && activeCommand->resolveSymbolForCommand(symbol, value);
}

bool CKeystoneArmInstruction::resolveSymbolForCommand(const char* symbol, uint64_t* value)
{
	Identifier name(symbol);
	if (name.size() == 0)
		return false;

	// Never implicitly create symbols inside Keystone's callback; all armips
	// expressions and labels are evaluated before invoking ks_asm.
	if (!Global.symbolTable.symbolExists(name, FileNum, getSection()))
		return false;

	std::shared_ptr<Label> label = Global.symbolTable.getLabel(name, FileNum, getSection());
	if (label == nullptr || !label->isDefined())
		return false;

	*value = static_cast<uint64_t>(label->getValue());
	return true;
}

bool CKeystoneArmInstruction::buildSource(std::string& rendered, bool& hasEvalError,
	bool& hasBranchTarget, int64_t& branchTarget, bool forceWide)
{
	rendered.clear();
	hasEvalError = false;
	hasBranchTarget = false;
	branchTarget = 0;

	const BranchKind branchKind = classifyBranchMnemonic(mnemonic);
	const bool isMovw = isMovwMnemonic(mnemonic);
	const bool isAdr = isAdrMnemonic(mnemonic);
	const bool isVfp = isVfpOrNeonMnemonic(mnemonic);
	const bool isIt = isItMnemonic(mnemonic);
	const bool isBlxReg = branchKind.isBlx && parts.size() >= 2 &&
		parts[1].kind == KeystoneStatementPart::Kind::Keyword;
	const bool isImmediateBranch = branchKind.isBranch && !isBlxReg;

	const auto provisionalValue = [&]() -> int64_t {
		if (isImmediateBranch)
		{
			if (!thumb || branchKind.isBlx)
				return (address + 4) & ~INT64_C(3);
			if (branchKind.isCbz)
				return (address + 4) & ~INT64_C(1);
			return address & ~INT64_C(1);
		}
		if (isAdr || pcRelAddSub)
			return (address + 4) & ~INT64_C(3);
		return 0;
	};

	// Translate native armips "add<c> Rd, =Expr" / "sub<c> Rd, =Expr" into PC-relative add/sub.
	if (pcRelAddSub && parts.size() == 4)
	{
		const size_t queueBefore = Logger::getQueueSize();
		ExpressionValue value = parts[3].expression.evaluate();
		int64_t target = 0;
		if (!value.isInt())
		{
			if (value.isValid() || Logger::getQueueSize() == queueBefore)
				Logger::queueError(Logger::Error, "Invalid expression type");
			hasEvalError = true;
			target = provisionalValue();
		}
		else
		{
			target = value.intValue;
		}

		const int64_t pcBase = thumb
			? ((address + 4) & ~INT64_C(3))
			: ((address + 8) & ~INT64_C(3));
		int64_t offset = target - pcBase;
		const bool negative = offset < 0;
		if (negative)
			offset = -offset;

		const std::string_view cond = stripWidthSuffix(mnemonic).substr(3);
		std::string opName;
		if (thumb)
			opName = (negative ? "subw" : "addw") + std::string(cond);
		else
			opName = (negative ? "sub" : "add") + std::string(cond);

		rendered = opName + " " + parts[1].text + ", pc, #" + formatKeystoneInteger(offset);
		return true;
	}

	int commaCount = 0;
	int braceDepth = 0;
	int bracketDepth = 0;
	bool hasPrev = false;
	KeystoneStatementPart::Kind prevKind = KeystoneStatementPart::Kind::Mnemonic;
	std::string prevText;

	auto appendPart = [&](KeystoneStatementPart::Kind kind, const std::string& text) {
		if (hasPrev && needsSpaceBefore(prevKind, prevText, kind, text))
			rendered += ' ';
		rendered += text;
		hasPrev = true;
		prevKind = kind;
		prevText = text;
	};

	for (KeystoneStatementPart& part : parts)
	{
		if (part.kind == KeystoneStatementPart::Kind::Mnemonic)
		{
			std::string opName = part.text;
			if (forceWide && thumb && !isIt && !branchKind.isBl && !branchKind.isBlx &&
				!hasWidthSuffix(opName))
			{
				opName += ".w";
			}
			appendPart(KeystoneStatementPart::Kind::Mnemonic, opName);
			continue;
		}

		if (part.kind == KeystoneStatementPart::Kind::Punct)
		{
			// Strip optional '#' on branch targets so Keystone treats the literal
			// as an absolute target virtual address rather than a PC-relative offset.
			if (isImmediateBranch && part.text == "#")
				continue;

			if (part.text == "," && braceDepth == 0 && bracketDepth == 0)
				commaCount++;
			else if (part.text == "{")
				braceDepth++;
			else if (part.text == "}" && braceDepth > 0)
				braceDepth--;
			else if (part.text == "[")
				bracketDepth++;
			else if (part.text == "]" && bracketDepth > 0)
				bracketDepth--;

			appendPart(KeystoneStatementPart::Kind::Punct, part.text);
			continue;
		}

		if (part.kind == KeystoneStatementPart::Kind::Keyword)
		{
			appendPart(KeystoneStatementPart::Kind::Keyword, part.text);
			continue;
		}

		bool evaluateAsExpression = (part.kind == KeystoneStatementPart::Kind::Expression);
		if (part.kind == KeystoneStatementPart::Kind::AmbiguousRegOrExpr)
		{
			if (Global.symbolTable.symbolExists(Identifier(part.text), FileNum, getSection()))
			{
				evaluateAsExpression = true;
			}
			else
			{
				appendPart(KeystoneStatementPart::Kind::Keyword, part.text);
				continue;
			}
		}

		if (evaluateAsExpression)
		{
			const size_t queueBefore = Logger::getQueueSize();
			ExpressionValue value = part.expression.evaluate();

			if (value.isFloat())
			{
				if (isVfp && part.reloc == KeystoneStatementPart::RelocModifier::None)
				{
					appendPart(KeystoneStatementPart::Kind::Expression, formatKeystoneFloat(value.floatValue));
					continue;
				}
				const int64_t floatBits = static_cast<int64_t>(
					static_cast<uint32_t>(getFloatBits(static_cast<float>(value.floatValue))));
				value = ExpressionValue(floatBits);
			}

			int64_t intVal = 0;
			if (!value.isInt())
			{
				if (value.isValid() || Logger::getQueueSize() == queueBefore)
					Logger::queueError(Logger::Error, "Invalid expression type");
				hasEvalError = true;
				intVal = provisionalValue();
			}
			else
			{
				intVal = value.intValue;
			}

			if (part.reloc == KeystoneStatementPart::RelocModifier::Lower16)
			{
				intVal = static_cast<int64_t>(static_cast<uint64_t>(intVal) & UINT64_C(0xFFFF));
			}
			else if (part.reloc == KeystoneStatementPart::RelocModifier::Upper16)
			{
				intVal = static_cast<int64_t>((static_cast<uint64_t>(intVal) >> 16) & UINT64_C(0xFFFF));
			}
			else if (isMovw && commaCount >= 1 && part.hasSymbolOrFunc)
			{
				// Patch code loads 32-bit addresses via MOVW/MOVT pairs; symbolic
				// MOVW operands contribute their lower 16 bits while plain literals
				// keep strict 16-bit range checking.
				intVal = static_cast<int64_t>(static_cast<uint64_t>(intVal) & UINT64_C(0xFFFF));
			}
			else if (isImmediateBranch && (!branchKind.isCbz || commaCount >= 1))
			{
				hasBranchTarget = true;
				branchTarget = intVal;
			}
			else
			{
				intVal = normalizeImmediateTo32Bit(intVal);
			}

			appendPart(KeystoneStatementPart::Kind::Expression, formatKeystoneInteger(intVal));
		}
	}

	return true;
}

bool CKeystoneArmInstruction::Validate(const ValidateState& state)
{
	address = g_fileManager->getVirtualAddress();
	if (g_fileManager->hasOpenFile() &&
		((thumb && (address & 1) != 0) || (!thumb && (address & 3) != 0)))
	{
		Logger::queueError(Logger::Warning,
			thumb ? "Opcode not halfword aligned" : "Opcode not word aligned");
	}

	const size_t oldAdvanceSize = lastAdvanceSize;
	encoding.clear();

	const bool isIt = isItMnemonic(mnemonic);
	const BranchKind branchKind = classifyBranchMnemonic(mnemonic);

	// Check active Thumb IT block transitions before assembling this instruction.
	if (activeItState.active)
	{
		if (!thumb)
		{
			Logger::queueError(Logger::Error, "Thumb IT block cannot continue in ARM mode");
			activeItState.reset();
		}
		else if (isIt)
		{
			Logger::queueError(Logger::Error, "Nested Thumb IT blocks are not supported");
			activeItState.reset();
			lastAdvanceSize = 0;
			return oldAdvanceSize != 0;
		}
		else if (activeItState.endianness != endianness)
		{
			Logger::queueError(Logger::Error, "Thumb IT block cannot change endianness");
			activeItState.valid = false;
		}
	}

	const bool insideItBlock = activeItState.active;

	if (insideItBlock && !activeItState.valid)
	{
		activeItState.renderedStatements.emplace_back();
		if (activeItState.renderedStatements.size() >= activeItState.expectedStatementCount)
			activeItState.reset();
		lastAdvanceSize = 0;
		return oldAdvanceSize != 0;
	}

	if (insideItBlock)
	{
		const int64_t expectedAddress = activeItState.startAddress +
			static_cast<int64_t>(activeItState.encodedPrefixSize);
		if (address != expectedAddress)
		{
			Logger::queueError(Logger::Error, "Thumb IT block instructions must be consecutive");
			activeItState.valid = false;
			activeItState.renderedStatements.emplace_back();
			if (activeItState.renderedStatements.size() >= activeItState.expectedStatementCount)
				activeItState.reset();
			lastAdvanceSize = 0;
			return oldAdvanceSize != 0;
		}
	}

	ks_engine* engine = getEngine(thumb, endianness);
	if (engine == nullptr)
	{
		Logger::queueError(Logger::Error, "Unable to initialize the Keystone ARM engine");
		lastAdvanceSize = 0;
		return oldAdvanceSize != 0;
	}

	std::string rendered;
	bool hasEvalError = false;
	bool hasBranchTarget = false;
	int64_t branchTarget = 0;
	buildSource(rendered, hasEvalError, hasBranchTarget, branchTarget, lockedWide);

	bool hasBranchAlignError = false;
	if (hasBranchTarget && !hasEvalError)
	{
		if (!thumb)
		{
			if (branchKind.isBlx)
			{
				if ((branchTarget & 1) != 0)
				{
					Logger::queueError(Logger::Error, "Branch target must be halfword aligned");
					hasBranchAlignError = true;
				}
			}
			else if ((branchTarget & 3) != 0)
			{
				Logger::queueError(Logger::Error, "Branch target must be word aligned");
				hasBranchAlignError = true;
			}
		}
		else
		{
			if (branchKind.isBlx)
			{
				if ((branchTarget & 3) != 0)
				{
					Logger::queueError(Logger::Error, "Branch target must be word aligned");
					hasBranchAlignError = true;
				}
			}
			else if ((branchTarget & 1) != 0)
			{
				Logger::queueError(Logger::Error, "Branch target must be halfword aligned");
				hasBranchAlignError = true;
			}
		}
	}

	if (hasBranchAlignError)
	{
		if (insideItBlock)
		{
			activeItState.valid = false;
			activeItState.renderedStatements.push_back(rendered);
			if (activeItState.renderedStatements.size() >= activeItState.expectedStatementCount)
				activeItState.reset();
		}
		const size_t alignAdvanceSize = (!thumb || branchKind.isBl || branchKind.isBlx) ? 4u : 2u;
		g_fileManager->advanceMemory(alignAdvanceSize);
		lastAdvanceSize = alignAdvanceSize;
		return oldAdvanceSize != lastAdvanceSize;
	}

	auto assembleInput = [&](const std::string& inputText, uint64_t asmAddr,
		unsigned char*& outBytes, size_t& outSize, size_t& outCount) -> int {
		activeCommand = this;
		const int res = ks_asm(engine, inputText.c_str(), asmAddr, &outBytes, &outSize, &outCount);
		activeCommand = nullptr;
		return res;
	};

	auto buildItInput = [&](const std::string& currentLine) -> std::string {
		std::ostringstream stream;
		for (size_t i = 0; i < activeItState.renderedStatements.size(); ++i)
		{
			if (i != 0)
				stream << '\n';
			stream << activeItState.renderedStatements[i];
		}
		if (!activeItState.renderedStatements.empty())
			stream << '\n';
		stream << currentLine;
		return stream.str();
	};

	const uint64_t assemblyAddress = insideItBlock
		? static_cast<uint64_t>(activeItState.startAddress)
		: static_cast<uint64_t>(address);
	std::string input = insideItBlock ? buildItInput(rendered) : rendered;

	unsigned char* assembled = nullptr;
	size_t assembledSize = 0;
	size_t statementCount = 0;
	int result = assembleInput(input, assemblyAddress, assembled, assembledSize, statementCount);

	// If forced wide suffix was rejected for an instruction without a .w variant,
	// fall back to the unsuffixed rendering.
	if (result != 0 && lockedWide && !hasEvalError)
	{
		if (assembled != nullptr)
		{
			ks_free(assembled);
			assembled = nullptr;
		}
		std::string fallbackRendered;
		bool dummyEvalErr = false;
		bool dummyHasTarget = false;
		int64_t dummyTarget = 0;
		buildSource(fallbackRendered, dummyEvalErr, dummyHasTarget, dummyTarget, false);
		rendered = std::move(fallbackRendered);
		input = insideItBlock ? buildItInput(rendered) : rendered;
		result = assembleInput(input, assemblyAddress, assembled, assembledSize, statementCount);
	}

	// In unified Thumb syntax, Keystone preserves CPSR for unsuffixed ALU
	// instructions outside an IT block and therefore emits 32-bit .W encodings.
	// armips traditionally selects the compact 16-bit Thumb encoding when one
	// exists. Try the 's' suffixed candidate and use it only when it produces a
	// single 16-bit instruction; explicit .w forms and Thumb-2-only encodings
	// remain unchanged.
	if (result == 0 && thumb && !insideItBlock && !isIt && !lockedWide && !pcRelAddSub &&
		assembledSize > 2 && isThumbNarrowAluMnemonic(mnemonic) &&
		rendered.size() > mnemonic.size() && rendered[mnemonic.size()] == ' ')
	{
		const std::string narrowInput = mnemonic + "s" + rendered.substr(mnemonic.size());
		unsigned char* narrowAssembled = nullptr;
		size_t narrowSize = 0;
		size_t narrowStatementCount = 0;
		const int narrowResult = assembleInput(narrowInput, assemblyAddress,
			narrowAssembled, narrowSize, narrowStatementCount);
		if (narrowResult == 0 && narrowSize == 2)
		{
			ks_free(assembled);
			assembled = narrowAssembled;
			assembledSize = narrowSize;
			statementCount = narrowStatementCount;
			narrowAssembled = nullptr;
		}
		if (narrowAssembled != nullptr)
			ks_free(narrowAssembled);
	}

	if (result != 0)
	{
		if (!hasEvalError)
		{
			const ks_err error = ks_errno(engine);
			Logger::queueError(Logger::Error, "Keystone ARM assembly failed for \"%s\": %s",
				input, ks_strerror(error));
		}
		if (assembled != nullptr)
			ks_free(assembled);

		if (insideItBlock)
		{
			activeItState.valid = false;
			activeItState.renderedStatements.push_back(rendered);
			if (activeItState.renderedStatements.size() >= activeItState.expectedStatementCount)
				activeItState.reset();
		}
		else if (thumb && isIt)
		{
			activeItState.active = true;
			activeItState.valid = false;
			activeItState.opener = this;
			activeItState.expectedStatementCount = getItExpectedStatementCount(mnemonic);
			activeItState.startAddress = address;
			activeItState.encodedPrefixSize = 0;
			activeItState.endianness = endianness;
			activeItState.renderedStatements.clear();
			activeItState.renderedStatements.push_back(rendered);
		}

		// When expression evaluation failed (e.g. an undefined forward constant),
		// advance by a provisional instruction width so pass-0 layout and
		// .autoregion size estimation stay realistic.
		const size_t provisionalSize = hasEvalError ? (thumb ? 2u : 4u) : 0u;
		if (provisionalSize != 0)
			g_fileManager->advanceMemory(provisionalSize);
		lastAdvanceSize = provisionalSize;
		return oldAdvanceSize != lastAdvanceSize;
	}

	const size_t prefixSize = insideItBlock ? activeItState.encodedPrefixSize : 0;
	if (assembledSize < prefixSize)
	{
		Logger::queueError(Logger::Error, "Keystone returned an invalid Thumb IT block encoding");
		if (insideItBlock)
			activeItState.valid = false;
	}
	else
	{
		encoding.assign(assembled + prefixSize, assembled + assembledSize);
	}
	ks_free(assembled);

	if (encoding.empty())
	{
		Logger::queueError(Logger::Error,
			"Keystone produced no code for \"%s\"; Thumb conditional instructions require an IT block",
			input);
	}

	if (insideItBlock)
	{
		activeItState.renderedStatements.push_back(rendered);
		activeItState.encodedPrefixSize = prefixSize + encoding.size();
		if (activeItState.renderedStatements.size() >= activeItState.expectedStatementCount)
			activeItState.reset();
	}
	else if (thumb && isIt)
	{
		activeItState.active = true;
		activeItState.valid = !encoding.empty();
		activeItState.opener = this;
		activeItState.expectedStatementCount = getItExpectedStatementCount(mnemonic);
		activeItState.startAddress = address;
		activeItState.encodedPrefixSize = encoding.size();
		activeItState.endianness = endianness;
		activeItState.renderedStatements.clear();
		activeItState.renderedStatements.push_back(rendered);
	}

	// Guard against 2B <-> 4B non-monotonic Thumb-2 size oscillation across passes.
	if (thumb && state.passes >= 1 && oldAdvanceSize == 2 && encoding.size() == 4)
	{
		widenCount++;
		if (widenCount >= 2)
			lockedWide = true;
	}

	g_fileManager->advanceMemory(encoding.size());
	lastAdvanceSize = encoding.size();
	return oldAdvanceSize != lastAdvanceSize;
}

void CKeystoneArmInstruction::Encode() const
{
	if (!encoding.empty())
		g_fileManager->write(const_cast<unsigned char*>(encoding.data()), encoding.size());
}

void CKeystoneArmInstruction::writeTempData(TempData& tempData) const
{
	tempData.writeLine(address, "   " + source);
}

std::unique_ptr<CAssemblerCommand> parseKeystoneArmOpcode(
	Parser& parser, bool thumb, Endianness endianness)
{
	if (parser.peekToken().type != TokenType::Identifier)
		return nullptr;

	// Skip parsing errors and side effects inside trivially false conditional
	// blocks (.if 0) and macro label-discovery scans.
	if (!parser.isInsideTrueBlock() || parser.isInitializingMacro())
	{
		while (!parser.atEnd() && parser.peekToken().type != TokenType::Separator)
			parser.eatToken();
		if (!parser.atEnd())
			parser.eatToken();
		return std::make_unique<DummyCommand>();
	}

	const Token firstToken = parser.peekToken();
	ParsedStatement statement = readStatement(parser);
	if (statement.hasParseError)
		return nullptr;

	if (thumb)
		removeRedundantWidthSuffix(statement);

	if (statement.hasLiteralPoolSyntax)
	{
		parser.printError(firstToken, "Literal-pool syntax (ldr ..., =value) is not supported by the ARMv7-A backend");
		return nullptr;
	}

	// Consume the trailing statement separator only after parsing succeeded.
	if (!parser.atEnd() && parser.peekToken().type == TokenType::Separator)
		parser.eatToken();

	return std::make_unique<CKeystoneArmInstruction>(
		std::move(statement.parts), std::move(statement.text),
		std::move(statement.mnemonic), thumb, endianness, statement.pcRelAddSub);
}

void resetKeystoneItValidationState()
{
	activeItState.reset();
}

void flushIncompleteKeystoneItBlock()
{
	if (!activeItState.active)
		return;

	if (activeItState.valid &&
		activeItState.renderedStatements.size() < activeItState.expectedStatementCount &&
		activeItState.opener != nullptr)
	{
		const auto savedFileInfo = Global.FileInfo;
		activeItState.opener->applyFileInfo();
		Logger::queueError(Logger::Error, "Incomplete Thumb IT block");
		Global.FileInfo = savedFileInfo;
	}

	activeItState.reset();
}

std::unique_ptr<CAssemblerCommand> ArmParser::parseKeystoneOpcode(
	Parser& parser, bool thumb, Endianness endianness)
{
	return parseKeystoneArmOpcode(parser, thumb, endianness);
}

#endif
