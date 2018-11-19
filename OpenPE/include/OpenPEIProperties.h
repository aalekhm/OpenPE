#pragma once
#include <xmemory>
#include "OpenPEStructures.h"

namespace OpenPE
{
	class PEIProperties
	{
		public:
			// Constructor
			virtual std::auto_ptr<PEIProperties> duplicate() const = 0;
			
			// Fills the PE Structures.
			virtual void createPE(uint32_t iSectionAlignment, uint16_t iSubsystem) = 0;
		public:
			// Destructor
			~PEIProperties() {};
		public:
			// Image
			virtual PEType							getPEType() const = 0;

		public:
			// PE HEADER

			// Returns Image base for PE(32-bit) & PE+(64-bit) respectively
			virtual uint32_t						getImageBase32() const = 0;
			virtual uint64_t						getImageBase64() const = 0;

			//Returns Image Entry Point
			virtual uint32_t						getEntryPoint() const = 0;
			// Sets Image Entry Point (Just the Header value)
			virtual void							setEntryPoint(uint32_t iNewEntryPoint) = 0;

			// Returns File alignment
			virtual uint32_t						getFileAlignment() const = 0;
			// Returns Section alignment
			virtual uint32_t						getSectionAlignment() const = 0;

			// Returns Heap size commit for PE(32-bit) & PE+(64-bit) respectively
			virtual uint32_t						getHeapSizeCommit32() const = 0;
			virtual uint64_t						getHeapSizeCommit64() const = 0;

			// Returns Heap size reserve for PE(32-bit) & PE+(64-bit) respectively
			virtual uint32_t						getHeapSizeReserve32() const = 0;
			virtual uint64_t						getHeapSizeReserve64() const = 0;

			// Returns Stack size commit for PE(32-bit) & PE+(64-bit) respectively
			virtual uint32_t						getStackSizeCommit32() const = 0;
			virtual uint64_t						getStackSizeCommit64() const = 0;

			// Returns Stack size reserve for PE(32-bit) & PE+(64-bit) respectively
			virtual uint32_t						getStackSizeReserve32() const = 0;
			virtual uint64_t						getStackSizeReserve64() const = 0;

			// Returns Size of the Image
			virtual uint32_t						getSizeOfImage() const = 0;

			// returns number of RVA's & Sizes (number of DATA_DIRECTORY entries)
			virtual uint32_t						getNumberOfRVAsAndSizes() const = 0;
			virtual void							setNumberOfRVAsAndSizes(uint32_t iNumberOfRVAsAndSizes) = 0;

			//Returns PE characteristics
			virtual uint32_t						getCharacteristics() const = 0;

			// Returns Size of headers
			virtual uint32_t						getSizeOfHeaders() const = 0;

			// Returns Subsystem
			virtual uint16_t						getSubsystem() const = 0;
			// Sets Subsystem value
			virtual void							setSubsystem(uint16_t iSubsystem) = 0;

			// Returns Size of Optional Header
			virtual	uint32_t						getSizeOfOptionalHeader() const = 0;

			//Returns PE signature
			virtual	uint16_t						getPESignature() const = 0;

			// Returns PE Magic
			virtual	uint16_t						getPEMagic() const = 0;

			// Returns Checksum of PE file from header
			virtual uint32_t						getChecksum() const = 0;
			// Sets Checksum of PE file
			virtual void							setChecksum(uint32_t iChecksum) = 0;

			// Returns Timestamp of PE file from header
			virtual uint32_t						getTimeDateStamp() const = 0;

			// Returns Machine field value of PE file from header
			virtual uint16_t						getMachine() const = 0;

			// Returns DLL Characteristics
			virtual	uint16_t						getDLLCharacteristics() const = 0;

			// Returns required operation system version (minor word)
			virtual	uint16_t						getMinorOSVersion() const = 0;

			// Returns required operation system version (major word)
			virtual	uint16_t						getMajorOSVersion() const = 0;

			// Returns required subsystem version (minor word)
			virtual	uint16_t						getMinorSubsystem() const = 0;

			// Returns required subsystem version (major word)
			virtual	uint16_t						getMajorSubsystem() const = 0;

		public:
			// DIRECTORIES

			// Returns true if directory exists
			virtual bool							directoryExists(uint32_t iDirectoryID) const = 0;

			// Returns Directory RVA
			virtual uint32_t						getDirectoryRVA(uint32_t iDirectoryID) const = 0;

			// Returns Directory Size
			virtual	uint32_t						getDirectorySize(uint32_t iDirectoryID) const = 0;
		public:
			// SECTIONS

			// Returns Number of Sections
			virtual uint16_t						getNumberOfSections() const = 0;

		public:
			virtual char*							getNTHeaderPtr() = 0;
			virtual const char*						getNTHeaderPtr() const = 0;

			virtual uint32_t						get_sizeOfNTHeader() const = 0;
			virtual uint32_t						get_sizeOfOptionalHeader() const = 0;

			virtual uint32_t						getBaseOfCode() const = 0;
			virtual uint32_t						getNeedeMagic() const = 0;	
	};
}