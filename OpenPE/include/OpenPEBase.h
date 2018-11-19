#pragma once

#include <istream>					// for 'std::istream'
#include "OpenPEException.h"
#include "OpenPEStructures.h"		// for PE all related structures.
#include "OpenPEIProperties.h"		// IProperties interface
#include "OpenPESection.h"
#include "OpenPEUtils.h"

namespace OpenPE
{
	class PEBase
	{
		public:
			// Constructor
			PEBase(std::istream& pFileStream, const PEIProperties& pProperties, bool bReadDebugRawData = true);

			PEBase(const PEBase& pe);
			PEBase& operator=(const PEBase& pe);
		public:
			// Destructor
			~PEBase();
		public:
			// Directories

			// Returns 'true' if Directory exists
			bool					directoryExists(uint32_t iDirectoryID) const;
			// Removes specified Directory
			void					removeDirectory(uint32_t iDirectoryID);

			// Returns Directory RVA
			uint32_t				getDirectoryRVA(uint32_t iDirectoryID) const;
			// Returns Directory Size
			uint32_t				getDirectorySize(uint32_t iDirectoryID) const;

			// Sets Directory RVA (just a value in PE Header, no movement occurs)
			void					setDirectoryRVA(uint32_t iDirectoryID, uint32_t iRVA);
			// Sets Directory Size (just a value in PE Header, no movement occurs)
			void					setDirectorySize(uint32_t iDirectoryID, uint32_t iRVA);

			// Returns 'true' if Image has Import Directory
			bool					hasImports() const;
			// Returns 'true' if Image has Export Directory
			bool					hasExports() const;
			// Returns 'true' if Image has Resources Directory
			bool					hasResources() const;
			// Returns 'true' if Image has Security Directory
			bool					hasSecurity() const;
			// Returns 'true' if Image has Relocations
			bool					hasReloc() const;
			// Returns 'true' if Image has TLS Directory
			bool					hasTLS() const;
			// Returns 'true' if Image has Config Directory
			bool					hasConfig() const;
			// Returns 'true' if Image has Bound Import Directory
			bool					hasBoundImport() const;
			// Returns 'true' if Image has Delayed Import Directory
			bool					hasDelayImport() const;
			// Returns 'true' if Image has COM Directory
			bool					isDotNet() const;
			// Returns 'true' if Image has Exception Directory
			bool					hasExceptionDirectory() const;
			// Returns 'true' if Image has Debug Directory
			bool					hasDebug() const;

			// Returns Subsystem
			uint16_t				getSubsystem() const;
			// Sets Subsystem value
			void					setSubsystem(uint16_t iSubsystem);

			// Returns true if image has console subsystem
			bool					isConsole() const;
			// Returns true if image has GUI subsystem
			bool					isGui() const;
	public:
			// Image Sections

			// Returns Number of Sections
			uint32_t				getNumberOfSections() const;

			// Returns Section from RVA inside it
			PESection&				getSectionFromRVA(uint32_t iRVA);
			const PESection&		getSectionFromRVA(uint32_t iRVA) const;

			// Returns Section from Directory ID
			PESection&				getSectionFromDirectory(uint32_t iDirectoryID);
			const PESection&		getSectionFromDirectory(uint32_t iDirectoryID) const;

			// Returns Section from VA inside it for PE32 & PE64 respectively
			PESection&				getSectionFromVA(uint32_t iVA);
			const PESection&		getSectionFromVA(uint32_t iVA) const;

			PESection&				getSectionFromVA(uint64_t iVA);
			const PESection&		getSectionFromVA(uint64_t iVA) const;

			// Returns Section from File Offset (4GB max)
			PESection&				getSectionFromFileOffset(uint32_t iFileOffset);
			const PESection&		getSectionFromFileOffset(uint32_t iFileOffset) const;

			////////////////////////////////////////////////////
			// Returns section TOTAL RAW/VIRTUAL data length from RVA inside section
			// If bIncludeHeaders = true, data from the beginning of PE file to SizeOfHeaders will be searched, too
			uint32_t				getSectionDataLengthFromRVA(uint32_t iRVA, SECTION_DATA_TYPE eSectionDataType = SECTION_DATA_RAW, bool bIncludeHeaders = false) const;

			// Returns section TOTAL RAW/VIRTUAL data length from VA inside section for PE32 and PE64 respectively
			// If bIncludeHeaders = true, data from the beginning of PE file to SizeOfHeaders will be searched, too
			uint32_t				getSectionDataLengthFromVA(uint32_t iVA, SECTION_DATA_TYPE eSectionDataType = SECTION_DATA_RAW, bool bIncludeHeaders = false) const;
			uint32_t				getSectionDataLengthFromVA(uint64_t iVA, SECTION_DATA_TYPE eSectionDataType = SECTION_DATA_RAW, bool bIncludeHeaders = false) const;
			////////////////////////////////////////////////////
			// Returns section remaining RAW/VIRTUAL data length from RVA to the end of section "s" (checks bounds)
			uint32_t				getSectionDataLengthFromRVA(const PESection& peSection, uint32_t iRVAInside, SECTION_DATA_TYPE eSectionDataType = SECTION_DATA_RAW) const;

			// Returns section remaining RAW/VIRTUAL data length from VA to the end of section "s" for PE32 and PE64 respectively (checks bounds)
			uint32_t				getSectionDataLengthFromVA(const PESection& peSection, uint32_t iVAInside, SECTION_DATA_TYPE eSectionDataType = SECTION_DATA_RAW) const;
			uint32_t				getSectionDataLengthFromVA(const PESection& peSection, uint64_t iVAInside, SECTION_DATA_TYPE eSectionDataType = SECTION_DATA_RAW) const;
			////////////////////////////////////////////////////
			// Returns section remaining RAW/VIRTUAL data length from RVA "rva_inside" to the end of section containing RVA "rva"
			// If bIncludeHeaders = true, data from the beginning of PE file to SizeOfHeaders will be searched, too
			uint32_t				getSectionDataLengthFromRVA(uint32_t iRVA, uint32_t iRVAInside, SECTION_DATA_TYPE eSectionDataType = SECTION_DATA_RAW, bool bIncludeHeaders = false) const;

			// Returns section remaining RAW/VIRTUAL data length from VA "va_inside" to the end of section containing VA "va" for PE32 and PE64 respectively
			// If bIncludeHeaders = true, data from the beginning of PE file to SizeOfHeaders will be searched, too
			uint32_t				getSectionDataLengthFromVA(uint32_t iVA, uint32_t iVAInside, SECTION_DATA_TYPE eSectionDataType = SECTION_DATA_RAW, bool bIncludeHeaders = false) const;
			uint32_t				getSectionDataLengthFromVA(uint64_t iVA, uint64_t iVAInside, SECTION_DATA_TYPE eSectionDataType = SECTION_DATA_RAW, bool bIncludeHeaders = false) const;
			////////////////////////////////////////////////////
			// If bIncludeHeaders = true, data from the beginning of PE file to SizeOfHeaders will be searched, too
			// Returns corresponding section data pointer from RVA inside section
			char*					getSectionDataFromRVA(uint32_t iRVA, bool bIncludeHeaders = false);
			const char*				getSectionDataFromRVA(uint32_t iRVA, SECTION_DATA_TYPE eSectionDataType = SECTION_DATA_RAW, bool bIncludeHeaders = false) const;

			// Returns corresponding section data pointer from VA inside section for PE32 and PE64 respectively
			char*					getSectionDataFromVA(uint32_t iVA, bool bIncludeHeaders = false);
			const char*				getSectionDataFromVA(uint32_t iVA, SECTION_DATA_TYPE eSectionDataType = SECTION_DATA_RAW, bool bIncludeHeaders = false) const;
			char*					getSectionDataFromVA(uint64_t iVA, bool bIncludeHeaders = false);
			const char*				getSectionDataFromVA(uint64_t iVA, SECTION_DATA_TYPE eSectionDataType = SECTION_DATA_RAW, bool bIncludeHeaders = false) const;
			////////////////////////////////////////////////////
			// Returns corresponding section data pointer from RVA inside section "s" (checks bounds)
			char*					getSectionDataFromRVA(PESection& peSection, uint32_t iRVA);
			const char*				getSectionDataFromRVA(const PESection& peSection, uint32_t iRVA, SECTION_DATA_TYPE eSectionDataType = SECTION_DATA_RAW) const;

			// Returns corresponding section data pointer from VA inside section "s" for PE32 and PE64 respectively (checks bounds)
			char*					getSectionDataFromVA(PESection& peSection, uint32_t iVA); //Always returns raw data
			const char*				getSectionDataFromVA(const PESection& peSection, uint32_t iVA, SECTION_DATA_TYPE eSectionDataType = SECTION_DATA_RAW) const;
			char*					getSectionDataFromVA(PESection& peSection, uint64_t iVA); //Always returns raw data
			const char*				getSectionDataFromVA(const PESection& peSection, uint64_t iVA, SECTION_DATA_TYPE eSectionDataType = SECTION_DATA_RAW) const;
			////////////////////////////////////////////////////

			//Returns corresponding section data pointer from RVA inside section "s" (checks bounds, checks sizes, the most safe function)
			template<typename T>
			T getSectionDataFromRVA(const PESection& s, uint32_t rva, SECTION_DATA_TYPE eSectionDataType = SECTION_DATA_RAW) const
			{
				if (iRVA >= peSection.getVirtualAddress() && iRVA < peSection.getVirtualAddress() + peSection.getAlignedVirtualSize(getSectionAlignment()) && PEUtils::isSumSafess(iRVA, sizeof(T)))
				{
					const std::string& sData = (eSectionDataType == SECTION_DATA_RAW) 
												? 
												peSection.getRawData() 
												: 
												peSection.getVirtualData(getSectionAlignment());

					//Don't check for underflow here, comparsion is unsigned
					if (sData.size() < iRVA - peSection.getVirtualAddress() + sizeof(T))
						throw PEException("RVA and requested data size does not exist inside section", PEException::PEEXCEPTION_RVA_DOESNT_NOT_EXISTS);

					return *reinterpret_cast<const T*>(sData.data() + iRVA - peSection.getVirtualAddress());
				}

				throw PEException("RVA not found inside section", PEException::rva_not_exists);
			}

			//Returns corresponding section data pointer from RVA inside section (checks iRVA, checks sizes, the most safe function)
			//If bIncludeHeaders = true, data from the beginning of PE file to SizeOfHeaders will be searched, too
			template<typename T>
			T getSectionDataFromRVA(uint32_t iRVA, SECTION_DATA_TYPE eSectionDataType = SECTION_DATA_RAW, bool bIncludeHeaders = false) const
			{
				//if RVA is inside of headers and we're searching them too...
				if (	bIncludeHeaders 
						&& 
						PEUtils::isSumSafe(iRVA, sizeof(T)) && (iRVA + sizeof(T) < m_sFullHeadersData.length())
				)
					return *reinterpret_cast<const T*>(&m_sFullHeadersData[iRVA]);

				const PESection& peSection = getSectionFromRVA(iRVA);
				const std::string& sData = (eSectionDataType == SECTION_DATA_RAW)
											? 
											peSection.getRawData() 
											: 
											peSection.getVirtualData(getSectionAlignment());

				//Don't check for underflow here, comparsion is unsigned
				if (sData.size() < iRVA - peSection.getVirtualAddress() + sizeof(T))
					throw PEException("RVA and requested data size does not exist inside section", PEException::PEEXCEPTION_RVA_DOESNT_NOT_EXISTS);

				return *reinterpret_cast<const T*>(sData.data() + iRVA - peSection.getVirtualAddress());
			}

			//Returns corresponding section data pointer from VA inside section "s" (checks bounds, checks sizes, the most safe function)
			template<typename T>
			T getSectionDataFromVA(const PESection& s, uint32_t iVA, SECTION_DATA_TYPE eSectionDataType = SECTION_DATA_RAW) const
			{
				return getSectionDataFromRVA<T>(s, getVAToRVA(iVA), eSectionDataType);
			}

			template<typename T>
			T getSectionDataFromVA(const PESection& s, uint64_t iVA, SECTION_DATA_TYPE eSectionDataType = SECTION_DATA_RAW) const
			{
				return getSectionDataFromRVA<T>(s, getVAToRVA(iVA), eSectionDataType);
			}

			//Returns corresponding section data pointer from VA inside section (checks rva, checks sizes, the most safe function)
			//If bIncludeHeaders = true, data from the beginning of PE file to SizeOfHeaders will be searched, too
			template<typename T>
			T section_data_from_va(uint32_t iVA, SECTION_DATA_TYPE eSectionDataType = SECTION_DATA_RAW, bool bIncludeHeaders = false) const
			{
				return getSectionDataFromRVA<T>(getVAToRVA(iVA), eSectionDataType, bIncludeHeaders);
			}

			template<typename T>
			T getSectionDataFromRVA(uint64_t iVA, SECTION_DATA_TYPE eSectionDataType = SECTION_DATA_RAW, bool bIncludeHeaders = false) const
			{
				return getSectionDataFromRVA<T>(getVAToRVA(iVA), eSectionDataType, bIncludeHeaders);
			}
	public:
			// PE Headers

			// Returns NT Headers Data Pointer
			virtual char*			getNTHeadersPtr() const;

			// Returns sizeof() NT Headers
			uint32_t				get_sizeofNTHeader() const;
			// Returns sizeof() Optional Header
			uint32_t				get_sizeOfOptionalHeader() const;

			// Returns Size of Headers
			uint32_t				getSizeOfHeaders() const;
			// Returns Size of Optional Header
			uint32_t				getSizeOfOptionalHeader() const;

			// Return the PE Signature
			uint32_t				getPESignature() const;

			// Returns number of RVA's & Sizes (number of DATA_DIRECTORY entries)
			uint32_t				getNumberOfRVAsAndSizes() const;
			// Sets number of RVA's & Sizes (number of DATA_DIRECTORY entries)
			void					setNumberOfRVAsAndSizes(uint32_t iNumberOfRVAsAndSizes);

			// Returns PE characteristics
			uint16_t				getCharacteristics() const;

			// Returns Checksum of PE file from Header
			uint32_t				getChecksum() const;
			// Sets Checksum of PE file
			void					setChecksum(uint32_t iChecksum);

			uint16_t				getPEMagic() const;
			uint16_t				getNeededMagic() const;

			// Returns Section alignment
			virtual uint32_t		getSectionAlignment() const;
			// Returns File alignment
			virtual uint32_t		getFileAlignment() const;

			// Returns Image Sections
			SECTION_LIST&			getImageSectionList();
			const SECTION_LIST&		getImageSectionList() const;

			// Returns Size of the Image
			virtual uint32_t		getSizeOfImage() const;

			// Returns Image Entry Point
			uint32_t				getEntryPoint() const;
			// Sets Image Entry Point (Just the value in PE Header)
			void					setEntryPoint(uint32_t iNewEntryPoint);

			// Returns Image base for PE(32-bit) & PE+(64-bit) respectively
			uint32_t				getImageBase32() const;
			uint64_t				getImageBase64() const;
		public:
			// Address Convertion

			// Virtual Address(VA) to Relative Virtual Address(RVA) convertion
			// for PE32 & PE64 respectively
			// Bound checks & Integer Overflow
			uint32_t				getVAToRVA(uint32_t VA, bool bBoundCheck = true) const;
			uint32_t				getVAToRVA(uint64_t VA, bool bBoundCheck = true) const;

			// Relative Virtual Address(RVA) to Virtual Address(VA) convertion
			// for PE32 & PE64 respectively
			uint32_t				getRVAToVA_32(uint32_t RVA) const;
			void					getRVAToVA_32(uint32_t RVA, uint32_t& VA) const;
			uint32_t				getRVAToVA_64(uint32_t RVA) const;
			void					getRVAToVA_64(uint32_t RVA, uint64_t& VA) const;

			// RVA to RAW File Offset convertion(4GB max)
			uint32_t				getRVAToFileOffset(uint32_t RVA) const;
			//  RAW to RVAFile Offset convertion(4GB max)
			uint32_t				getFileOffsetToRVA(uint32_t iFileOffset) const;

			// RVA from Section Offset
			uint32_t				getRVAFromSectionOffset(const PESection& peSection, uint32_t iRawOffsetFromSectionStart);
		public:
			// Image

			// Returns the PE type (PE or PE+) from PEType enumeration of this Image
			static PEType			getPEType(std::istream& pFileStream);
			PEType					getPEType() const;
			
			// Returns true if Image has an Overlay
			bool					hasOverlay() const;
		private:
			static const uint32_t	MAXIMUM_NUMBER_OF_SECTIONS = 0x60;
			static const uint32_t	MINIMUM_FILE_ALIGNMENT = 512;
		private:
			// Reads & checks DOS headers from istream
			void					readDOSHeader(std::istream& pFileStream);
		public:
			// Reads & checks DOS headers from istream
			static void				readDOSHeader(std::istream& pFileStream, Image_Dos& _dosHeader);

			// Reads & checks PE Headers/Sections/Data
			void					readPE(std::istream& pFileStream, bool bReadDebugRawData);
	private:
			// 
			Image_Dos				m_DOSHeader;

			// Rich (stub) overlay data (for MSVS)
			std::string				m_sRichOverlay;

			// List of Image Sections
			SECTION_LIST			m_vSections;

			// True if Image has an Overlay
			bool					m_bHasOverlay;

			// Raw SizeOfHeader - sized Data from the beginning of Image
			std::string				m_sFullHeadersData;

			PEIProperties*			m_pProperties;
		private:
			// RAW file offset to section convertion helpers (4GB max)
			SECTION_LIST::iterator PEBase::getFileOffsetToSection(uint32_t iFileOffset);
			SECTION_LIST::const_iterator PEBase::getFileOffsetToSection(uint32_t iFileOffset) const;
	};
}