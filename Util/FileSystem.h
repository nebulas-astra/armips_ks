#pragma once

#ifdef ARMIPS_USE_STD_FILESYSTEM

#include <filesystem>
#include <fstream>

namespace fs
{
	using namespace std::filesystem;
	using ifstream = std::ifstream;
	using ofstream = std::ofstream;
	using fstream = std::fstream;
}

#else

#include <ghc/fs_fwd.hpp>

#include <fstream>
#include <ios>

namespace fs
{
	using namespace ghc::filesystem;

	// ghc::filesystem's stream wrappers only use the wide Windows API for
	// compilers that do not define __GNUC__. With GCC they hand the UTF-8 path
	// to fopen(), which interprets it as the ANSI code page, so non-ASCII file
	// names cannot be opened. Open through the wide CRT entry point on Windows
	// instead. The definitions live in FileSystem.cpp: including the ghc
	// implementation header here would pull in <windows.h>, whose unscoped
	// TokenType enumerator clashes with armips' TokenType enum.
	class ifstream : public std::ifstream
	{
	public:
		ifstream() = default;
		explicit ifstream(const path& fileName, std::ios_base::openmode mode = std::ios_base::in);
		void open(const path& fileName, std::ios_base::openmode mode = std::ios_base::in);
	};

	class ofstream : public std::ofstream
	{
	public:
		ofstream() = default;
		explicit ofstream(const path& fileName, std::ios_base::openmode mode = std::ios_base::out);
		void open(const path& fileName, std::ios_base::openmode mode = std::ios_base::out);
	};

	class fstream : public std::fstream
	{
	public:
		fstream() = default;
		explicit fstream(const path& fileName, std::ios_base::openmode mode = std::ios_base::in | std::ios_base::out);
		void open(const path& fileName, std::ios_base::openmode mode = std::ios_base::in | std::ios_base::out);
	};
}

#endif
