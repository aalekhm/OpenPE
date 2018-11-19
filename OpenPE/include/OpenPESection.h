#pragma once
#include <string>
#include <vector>
#include "OpenPEStructures.h"

namespace OpenPE
{
	// Enumeration of Section Data type, used in the functions below
	enum SECTION_DATA_TYPE
	{
		SECTION_DATA_RAW,
		SECTION_DATA_VIRTUAL
	};

	class PESection
	{
		public:
			// Default Constructor
			PESection();

			// Sets the name of the Section(Stripped off to 8 characters)
			void					SetName(const std::string& sName);

			// Returns the Name of the Section
			const std::string		GetName() const;

			// Sets Attributes of the Section
			PESection&				Readable(bool bReadable);
			PESection&				Writable(bool bWritable);
			PESection&				Executable(bool bExecutable);
			PESection&				Shared(bool bShared);
			PESection&				Discardable(bool bDiscardable);

			// Returns  Attributes of the Section
			bool					Readable();
			bool					Writable();
			bool					Executable();
			bool					Shared();
			bool					Discardable();

			// Returns true if Section has no raw data
			bool					empty() const;

			// Return raw section data from File image
			std::string&			getRawData();
			const std::string&		getRawData() const;

			// Returns mapped virtual section data
			std::string&			getVirtualData(uint32_t iSectionAlignment);
			const std::string&		getVirtualData(uint32_t iSectionAlignment) const;

		public:
			// Header getters
			// Returns Section virtual size
			uint32_t				getVirtualSize() const;

			// Returns Section virtual address, RVA
			uint32_t				getVirtualAddress() const;

			// Returns Size of Raw Data
			uint32_t				getSizeOfRawData() const;

			// Returns pointer to Raw Section Data in PE File
			uint32_t				getPointerToRawData() const;

			// Returns Section Characteristics
			uint32_t				getCharacteristics() const;

			// Returns Raw Image Section Header
			Image_Section_Header&			getRawHeader();
			const	Image_Section_Header&	getRawHeader() const;

		public:
			// Aligned Size Calculations
			// Calculate aligned virtual Section Size
			uint32_t				getAlignedVirtualSize(uint32_t iSectionAlignment) const;

			// Calculate aligned Raw Section Size
			uint32_t				getAlignedRawSize(uint32_t iFileAlignment) const;
		public:
			// Set the Size of Raw Section
			void					setSizeOfRawData(uint32_t iSizeOfRawData);

			// Sets pointer to Section Raw Data
			void					setPointerToRawData(uint32_t iPointerToRawData);

			// Sets Section Characteristics
			void					setCharacteristics(uint32_t iCharacteristics);

			// Sets Raw Section Data from File Image
			void					setRawData(const std::string& sData);
		public:
			// Setters, be careful
			// Sets Section Virtual Size (doesn't set internal aligned virtual size, changes only header value)
			// Better use PEBase::setSectionVirtualSize
			void					setVirtualSize(uint32_t iVirtualSize);

			// Sets Section Virtual Address
			void					setVirtualAddress(uint32_t iVirtualAddress);
		private:
			// Section Header
			Image_Section_Header	m_SectionHeader;

			// Maps Virtual Section Data
			void					mapVirtual(uint32_t iSectionAlignement) const;

			// Unmaps Virtual Section Data
			void					unmapVirtual() const;

			// Set Flag(Attribute of Section)
			PESection&				setFlag(uint32_t iFlag, bool bSetFlag);

			// Old Size of Section (stored after mapping of Virtual Section Memory)
			mutable	std::size_t		m_iOldSize;

			// Section Raw/Virtual Data
			mutable std::string		m_sRawData;
	};

	typedef std::vector<PESection>	SECTION_LIST;
}