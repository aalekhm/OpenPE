#include <string.h>
#include "OpenPEDotNet.h"

namespace OpenPE
{
	// Deafult constructor
	PEBasicDotNetInfo::PEBasicDotNetInfo()
	{
		memset(&m_CLR20Header, 0, sizeof(IMAGE_CLR20_HEADER));
	}

	// Constructor from data
	PEBasicDotNetInfo::PEBasicDotNetInfo(const IMAGE_CLR20_HEADER& imgClr20Header)
	: m_CLR20Header(imgClr20Header)
	{
	}

	// Returns Major Runtime version
	uint16_t PEBasicDotNetInfo::getMajorRuntimeVersion() const
	{
		return m_CLR20Header.iMajorRuntimeVersion;
	}

	// Returns Minor Runtime version
	uint16_t PEBasicDotNetInfo::getMinorRuntimeVersion() const
	{
		return m_CLR20Header.iMinorRuntimeVersion;
	}

	// Returns RVA of MetaData (Symbol Table Startup information)
	uint32_t PEBasicDotNetInfo::getRVAOfMetaData() const
	{
		return m_CLR20Header.ImgDataDir_MetaData.RVA;
	}

	// Returns Size of MetaData (Symbol Table Startup information)
	uint32_t PEBasicDotNetInfo::getSizeOfMetaData() const
	{
		return m_CLR20Header.ImgDataDir_MetaData.Size;
	}

	// Returns Flags
	uint32_t PEBasicDotNetInfo::getFlags() const
	{
		return m_CLR20Header.iFlags;
	}

	// Returns true if EntryPoint is native
	bool PEBasicDotNetInfo::isNativeEntryPoint() const
	{
		return (m_CLR20Header.iFlags & COMIMAGE_FLAGS_NATIVE_ENTRYPOINT) ? true : false;
	}

	// Returns true of 32-bit required
	bool PEBasicDotNetInfo::is32BitRequired() const
	{
		return (m_CLR20Header.iFlags & COMIMAGE_FLAGS_32BITREQUIRED) ? true : false;
	}

	// Returns true if image is IL library
	bool PEBasicDotNetInfo::isILLibrary() const
	{
		return (m_CLR20Header.iFlags & COMIMAGE_FLAGS_IL_LIBRARY) ? true : false;
	}

	// Returns true if image uses IL only
	bool PEBasicDotNetInfo::isILOnly() const
	{
		return (m_CLR20Header.iFlags & COMIMAGE_FLAGS_ILONLY) ? true : false;
	}

	// Returns Entry Point RVA (if Entry Point is native)
	// Returns Entry Point managed token (if Entry Point is managed)
	uint32_t PEBasicDotNetInfo::getEntryPointRVAOrToken() const
	{
		return m_CLR20Header.iEntryPointToken;
	}

	// Returns RVA of Managed Resources
	uint32_t PEBasicDotNetInfo::getRVAOfResources() const
	{
		return m_CLR20Header.ImgDataDir_Resources.RVA;
	}

	// Returns Size of Managed Resources
	uint32_t PEBasicDotNetInfo::getSizeOfResources() const
	{
		return m_CLR20Header.ImgDataDir_Resources.Size;
	}

	// Returns RVA of Strong Name Signature
	uint32_t PEBasicDotNetInfo::getRVAOfStrongNameSignature() const
	{
		return m_CLR20Header.ImgDataDir_StrongNameSignature.RVA;
	}

	// Returns Size of Strong Name Signature
	uint32_t PEBasicDotNetInfo::getSizeOfStrongNameSignature() const
	{
		return m_CLR20Header.ImgDataDir_StrongNameSignature.Size;
	}

	// Returns RVA of Code Manager Table
	uint32_t PEBasicDotNetInfo::getRVAOfCodeManagerTable() const
	{
		return m_CLR20Header.ImgDataDir_CodeManagerTable.RVA;
	}

	// Returns Size of Code Manager Table
	uint32_t PEBasicDotNetInfo::getSizeOfCodeManagerTable() const
	{
		return m_CLR20Header.ImgDataDir_CodeManagerTable.Size;
	}

	// Returns RVA of VTable Fixups
	uint32_t PEBasicDotNetInfo::getRVAOfVTableFixups() const
	{
		return m_CLR20Header.ImgDataDir_VTableFixups.RVA;
	}

	// Returns Size of VTable Fixups
	uint32_t PEBasicDotNetInfo::getSizeOfVTableFixups() const
	{
		return m_CLR20Header.ImgDataDir_VTableFixups.Size;
	}

	// Returns RVA of Export Address Table Jumps
	uint32_t PEBasicDotNetInfo::getRVAOfExportAddressTableJumps() const
	{
		return m_CLR20Header.ImgDataDir_ExportAddressTableJumps.RVA;
	}

	// Returns Size of Export Address Table Jumps
	uint32_t PEBasicDotNetInfo::getSizeOfExportAddressTableJumps() const
	{
		return m_CLR20Header.ImgDataDir_ExportAddressTableJumps.Size;
	}

	// Returns RVA of Managed Native Header
	// (precompiled header info, usually set to zero, for internal use)
	uint32_t PEBasicDotNetInfo::getRVAOfManagedNativeHeader() const
	{
		return m_CLR20Header.ImgDataDir_ManagedNativeHeader.RVA;
	}

	// Returns Size of Managed Native Header
	// (precompiled header info, usually set to zero, for internal use)
	uint32_t PEBasicDotNetInfo::getSizeOfManagedNativeHeader() const
	{
		return m_CLR20Header.ImgDataDir_ManagedNativeHeader.Size;
	}

	// Returns Basic .NET information
	// If image is native, throws an exception
	const PEBasicDotNetInfo	getBasicDotNetInfo(const PEBase& peBase)
	{
		// If there is no debug directory, return empty list
		if (NOT peBase.isDotNet())
		{
			throw PEException("Image does not have managed code", PEException::PEEXCEPTION_IMAGE_DOES_NOT_HAVE_MANAGED_CODE);
		}

		//Return basic .NET information
		return PEBasicDotNetInfo(peBase.getSectionDataFromRVA<IMAGE_CLR20_HEADER>(peBase.getDirectoryRVA(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR), SECTION_DATA_VIRTUAL, true));
	}
}