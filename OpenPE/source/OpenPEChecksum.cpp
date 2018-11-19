#include "OpenPEChecksum.h"
#include "OpenPEStructures.h"
#include "OpenPEBase.h"
#include "OpenPEUtils.h"

//#define SAVE_ISTREAM_STATE(__iFileStream__) \
//	std::ios_base::iostate iState = __iFileStream__.exceptions(); \
//	std::streamoff oldStreamOffset = __iFileStream__.tellg(); \
//
//#define RESTORE_ISTREAM_STATE(__iFileStream__) \
//	__iFileStream__.exceptions(iState); \
//	__iFileStream__.seekg(oldStreamOffset); \
//	__iFileStream__.clear(); \

namespace OpenPE
{
	//uint32_t calculateChecksum(std::istream& iFileStream)
	//{
	//	// Save Stream State
	//	SAVE_ISTREAM_STATE(iFileStream);

	//	// Checksum value
	//	unsigned long long iChecksum = 0;

	//	try
	//	{
	//		Image_Dos		_dosImage;

	//		// Check if the File Stream is good.
	//		iFileStream.exceptions(std::ios::goodbit);

	//		// Read DOS Header
	//		PEBase::readDOSHeader(iFileStream, _dosImage);

	//		// Calculate PE Checksum
	//		iFileStream.seekg(0);
	//		unsigned long long _Max = 0xFFFFFFFF;
	//		_Max++;

	//		// "Checksum" field position in Optional PE Headers is always at 64 both foe PE & PE+
	//		static const unsigned long long __ChecksumPositionInOptionalHeader = 64;

	//		// Calculate real PE Headers "Checksum" at field position
	//		unsigned long long _RealChecksum = _dosImage.PointerToPEHeader + sizeof(Image_COFF_FileHeader) + __ChecksumPositionInOptionalHeader;

	//		// Calculate Checksum for each byte of the file
	//		std::streamoff iFileSize = PEUtils::getFileSize(iFileStream);
	//		for (long long i = 0; i < iFileSize; i++)
	//		{
	//			unsigned long dWord = 0;

	//			// Read dWord from the file
	//			iFileStream.read(reinterpret_cast<char*>(&dWord), sizeof(unsigned long));

	//			// Skip "Checksum" DWORD
	//			if (i == _RealChecksum)
	//				continue;

	//			// Calculate Checksum
	//			iChecksum = (iChecksum & 0xFFFFFFFF) + dWord + (iChecksum >> 32);
	//			if (iChecksum > _Max)
	//				iChecksum = (iChecksum & 0xFFFFFFFF) + (iChecksum >> 32);
	//		}

	//		// Finish Checksum
	//		iChecksum = (iChecksum & 0xFFFFFFFF) + (iChecksum >> 16);
	//		iChecksum = (iChecksum) + (iChecksum >> 16);
	//		iChecksum = iChecksum & 0xFFFF;

	//		iChecksum += static_cast<unsigned long>(iFileSize);
	//	}
	//	catch (std::exception&)
	//	{
	//		// If something went wrong, Restore the istream state.
	//		RESTORE_ISTREAM_STATE(iFileStream);
	//	}

	//	// Restore istream state.
	//	RESTORE_ISTREAM_STATE(iFileStream);

	//	// Return Checksum
	//	return static_cast<uint32_t>(iChecksum);
	//}
}