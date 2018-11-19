#pragma once

#include "OpenPEStructures.h"
#include "OpenPEBase.h"

namespace OpenPE
{
	// Class representing basic .NET information
	class PEBasicDotNetInfo
	{
		public:
			// Deafult constructor
			PEBasicDotNetInfo();

			// Constructor from data
			explicit	PEBasicDotNetInfo(const IMAGE_CLR20_HEADER& imgClr20Header);

			// Returns Major Runtime version
			uint16_t	getMajorRuntimeVersion() const;
			// Returns Minor Runtime version
			uint16_t	getMinorRuntimeVersion() const;

			// Returns RVA of MetaData (Symbol Table Startup information)
			uint32_t	getRVAOfMetaData() const;
			// Returns Size of MetaData (Symbol Table Startup information)
			uint32_t	getSizeOfMetaData() const;

			// Returns Flags
			uint32_t	getFlags() const;

			// Returns true if EntryPoint is native
			bool		isNativeEntryPoint() const;
			// Returns true of 32-bit required
			bool		is32BitRequired() const;
			// Returns true if image is IL library
			bool		isILLibrary() const;
			// Returns true if image uses IL only
			bool		isILOnly() const;

			// Returns Entry Point RVA (if Entry Point is native)
			// Returns Entry Point managed token (if Entry Point is managed)
			uint32_t	getEntryPointRVAOrToken() const;

			// Returns RVA of Managed Resources
			uint32_t	getRVAOfResources() const;
			// Returns Size of Managed Resources
			uint32_t	getSizeOfResources() const;

			// Returns RVA of Strong Name Signature
			uint32_t	getRVAOfStrongNameSignature() const;
			// Returns Size of Strong Name Signature
			uint32_t	getSizeOfStrongNameSignature() const;

			// Returns RVA of Code Manager Table
			uint32_t	getRVAOfCodeManagerTable() const;
			// Returns Size of Code Manager Table
			uint32_t	getSizeOfCodeManagerTable() const;

			// Returns RVA of VTable Fixups
			uint32_t	getRVAOfVTableFixups() const;
			// Returns Size of VTable Fixups
			uint32_t	getSizeOfVTableFixups() const;

			// Returns RVA of Export Address Table Jumps
			uint32_t	getRVAOfExportAddressTableJumps() const;
			// Returns Size of Export Address Table Jumps
			uint32_t	getSizeOfExportAddressTableJumps() const;

			// Returns RVA of Managed Native Header
			// (precompiled header info, usually set to zero, for internal use)
			uint32_t	getRVAOfManagedNativeHeader() const;
			// Returns Size of Managed Native Header
			// (precompiled header info, usually set to zero, for internal use)
			uint32_t	getSizeOfManagedNativeHeader() const;
	private:
			IMAGE_CLR20_HEADER	m_CLR20Header;
	};

	// Returns Basic .NET information
	// If image is native, throws an exception
	const PEBasicDotNetInfo		getBasicDotNetInfo(const PEBase& peBase);
}