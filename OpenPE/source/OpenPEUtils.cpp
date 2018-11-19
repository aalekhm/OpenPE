#include "OpenPEUtils.h"

namespace OpenPE
{
	std::streamoff PEUtils::getFileSize(std::istream& iFileStreamIn)
	{
		// Store the old stream offset
		std::streamoff oldStreamOffset = iFileStreamIn.tellg();

		iFileStreamIn.seekg(0, std::ios::end);
		std::streamoff iFileSize = iFileStreamIn.tellg();

		// Restore to old stream offset
		iFileStreamIn.seekg(oldStreamOffset);

		return iFileSize;
	}
}
