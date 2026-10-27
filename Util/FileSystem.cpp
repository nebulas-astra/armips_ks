// The ghc implementation has to be included before the forwarding header,
// which defines GHC_FILESYSTEM_FWD and would otherwise suppress it.
#ifndef ARMIPS_USE_STD_FILESYSTEM
#include <ghc/fs_impl.hpp>
#endif

#include "Util/FileSystem.h"

#ifndef ARMIPS_USE_STD_FILESYSTEM
namespace fs
{
	ifstream::ifstream(const path& fileName, std::ios_base::openmode mode)
	{
		open(fileName, mode);
	}

	void ifstream::open(const path& fileName, std::ios_base::openmode mode)
	{
#ifdef _WIN32
		std::ifstream::open(fileName.wstring().c_str(), mode);
#else
		std::ifstream::open(fileName.string().c_str(), mode);
#endif
	}

	ofstream::ofstream(const path& fileName, std::ios_base::openmode mode)
	{
		open(fileName, mode);
	}

	void ofstream::open(const path& fileName, std::ios_base::openmode mode)
	{
#ifdef _WIN32
		std::ofstream::open(fileName.wstring().c_str(), mode);
#else
		std::ofstream::open(fileName.string().c_str(), mode);
#endif
	}

	fstream::fstream(const path& fileName, std::ios_base::openmode mode)
	{
		open(fileName, mode);
	}

	void fstream::open(const path& fileName, std::ios_base::openmode mode)
	{
#ifdef _WIN32
		std::fstream::open(fileName.wstring().c_str(), mode);
#else
		std::fstream::open(fileName.string().c_str(), mode);
#endif
	}
}
#endif
