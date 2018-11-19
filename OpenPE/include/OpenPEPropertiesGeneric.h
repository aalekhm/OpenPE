#pragma once
#include "OpenPEIProperties.h"

namespace OpenPE
{
	template<
		typename		NTHeadersType,
		typename		OptionalHeadersType,
		uint32_t		iIDValue,
		typename		BaseSizeType,
		BaseSizeType	ImportSnapFlagValue,
		typename		TLSStructType,
		typename		ConfigStructType
	>
	class PETypes
	{
		public:
			typedef NTHeadersType				NTHeader;							// NT Header
			typedef OptionalHeadersType			OptionalHeader;						// NT Optional Header
			typedef BaseSizeType				BaseSize;							// BaseSize: DWORD(32-bit) or ULONGLONG(64-bit)
			typedef TLSStructType				TLSStruct;							// TLS Structure type
			typedef ConfigStructType			ConfigStruct;						// Configuration Structure type

			static const uint32_t				ID = iIDValue;					// Magic for PE(32-bit) / PE+(64-bit)
			static const BaseSizeType			ImportSnapFlag = ImportSnapFlagValue;	// Import Snap Flag value
	};

	template<typename PEClassType>
	class PEPropertiesGeneric : public PEIProperties
	{
		public:
			// Constructor
			virtual std::auto_ptr<PEIProperties>	duplicate() const;

			// Fills the PE Structures
			virtual void							createPE(uint32_t iSectionAlignment, uint16_t iSubsystem);
		public:
			// Destructor
			virtual									~PEPropertiesGeneric();

		public:
			// Image
			virtual PEType							getPEType() const;

		public:
			// PE HEADER

			// Returns Image base for PE(32-bit) & PE+(64-bit) respectively
			virtual uint32_t						getImageBase32() const;
			virtual uint64_t						getImageBase64() const;

			//Returns Image Entry Point
			virtual uint32_t						getEntryPoint() const;
			// Sets Image Entry Point (Just the Header value)
			virtual void							setEntryPoint(uint32_t iNewEntryPoint);

			// Returns File alignment
			virtual uint32_t						getFileAlignment() const;
			// Returns Section alignment
			virtual uint32_t						getSectionAlignment() const;

			// Returns Heap size commit for PE(32-bit) & PE+(64-bit) respectively
			virtual uint32_t						getHeapSizeCommit32() const;
			virtual uint64_t						getHeapSizeCommit64() const;

			// Returns Heap size reserve for PE(32-bit) & PE+(64-bit) respectively
			virtual uint32_t						getHeapSizeReserve32() const;
			virtual uint64_t						getHeapSizeReserve64() const;

			// Returns Stack size commit for PE(32-bit) & PE+(64-bit) respectively
			virtual uint32_t						getStackSizeCommit32() const;
			virtual uint64_t						getStackSizeCommit64() const;

			// Returns Stack size reserve for PE(32-bit) & PE+(64-bit) respectively
			virtual uint32_t						getStackSizeReserve32() const;
			virtual uint64_t						getStackSizeReserve64() const;

			// Returns Size of the Image
			virtual uint32_t						getSizeOfImage() const;

			// returns number of RVA's & Sizes (number of DATA_DIRECTORY entries)
			virtual uint32_t						getNumberOfRVAsAndSizes() const;
			void									setNumberOfRVAsAndSizes(uint32_t iNumberOfRVAsAndSizes);

			//Returns PE characteristics
			virtual uint32_t						getCharacteristics() const;

			// Returns Size of headers
			virtual uint32_t						getSizeOfHeaders() const;

			// Returns Subsystem
			virtual uint16_t						getSubsystem() const;
			// Sets Subsystem value
			virtual void							setSubsystem(uint16_t iSubsystem);

			// Returns Size of Optional Header
			virtual	uint32_t						getSizeOfOptionalHeader() const;

			//Returns PE signature
			virtual	uint16_t						getPESignature() const;

			// Returns PE Magic
			virtual	uint16_t						getPEMagic() const;

			// Returns Checksum of PE file from header
			virtual uint32_t						getChecksum() const;
			// Sets Checksum of PE file
			virtual void							setChecksum(uint32_t iChecksum);

			// Returns Timestamp of PE file from header
			virtual uint32_t						getTimeDateStamp() const;

			// Returns Machine field value of PE file from header
			virtual uint16_t						getMachine() const;

			// Returns DLL Characteristics
			virtual	uint16_t						getDLLCharacteristics() const;

			// Returns required operation system version (minor word)
			virtual	uint16_t						getMinorOSVersion() const;

			// Returns required operation system version (major word)
			virtual	uint16_t						getMajorOSVersion() const;

			// Returns required subsystem version (minor word)
			virtual	uint16_t						getMinorSubsystem() const;

			// Returns required subsystem version (major word)
			virtual	uint16_t						getMajorSubsystem() const;

		public:
			// DIRECTORIES

			// Returns true if directory exists
			virtual bool							directoryExists(uint32_t iDirectoryID) const;

			// Returns Directory RVA
			virtual uint32_t						getDirectoryRVA(uint32_t iDirectoryID) const;

			// Returns Directory Size
			virtual	uint32_t						getDirectorySize(uint32_t iDirectoryID) const;
		public:
			// SECTIONS

			// Returns Number of Sections
			virtual uint16_t						getNumberOfSections() const;

		public:
			virtual char*							getNTHeaderPtr();
			virtual const char*						getNTHeaderPtr() const;

			virtual uint32_t						get_sizeOfNTHeader() const;
			virtual uint32_t						get_sizeOfOptionalHeader() const;

			virtual uint32_t						getBaseOfCode() const;
			virtual uint32_t						getNeedeMagic() const;

		protected:
			// NT Header PE(32) / PE+(64-bit)
			typename PEClassType::NTHeader			m_NTHeader;
	};

	// The 2 typedefs for PE(32-bit) & PE+(64-bit)
	typedef PETypes<Image_NT_Headers32,
					Image_COFF_OptionalHeader32, 
					IMAGE_NT_OPTIONAL_HDR32_MAGIC, 
					uint32_t, 
					IMAGE_ORDINAL_FLAG32,
					Image_TLS_Directory32,
					Image_Load_Config_Directory32>	PETypeClass32;

	typedef PETypes<Image_NT_Headers64,
					Image_COFF_OptionalHeader64, 
					IMAGE_NT_OPTIONAL_HDR64_MAGIC, 
					uint64_t, 
					IMAGE_ORDINAL_FLAG64,
					Image_TLS_Directory64,
					Image_Load_Config_Directory64>	PETypeClass64;

	typedef	PEPropertiesGeneric<PETypeClass32>		PEProperties32;
	typedef	PEPropertiesGeneric<PETypeClass64>		PEProperties64;
}