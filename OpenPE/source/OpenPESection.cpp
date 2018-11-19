#include "OpenPESection.h"
#include <algorithm>
#include <string>
#include "OpenPEUtils.h"

namespace OpenPE
{
	// Default Constructor
	PESection::PESection()
		: m_iOldSize(static_cast<size_t>(-1))
	{
		memset(&m_SectionHeader, 0, sizeof(Image_Section_Header));
	}

	// Sets the name of the Section(Stripped off to 8 characters)
	void PESection::SetName(const std::string& sName)
	{
		memset(m_SectionHeader.Name, 0, sizeof(m_SectionHeader.Name));
		memcpy(m_SectionHeader.Name, sName.c_str(), std::min<size_t>(sName.length(), sizeof(m_SectionHeader.Name)));
	}

	// Returns the Name of the Section
	const std::string PESection::GetName() const
	{
		char buf[9] = { 0 };
		memcpy(buf, m_SectionHeader.Name, 8);

		return std::string(buf);
	}

	// Sets Attributes of the Section
	PESection& PESection::Readable(bool bReadable)
	{
		return setFlag(IMAGE_SCN_MEM_READ, bReadable);
	}

	PESection& PESection::Writable(bool bWritable)
	{
		return setFlag(IMAGE_SCN_MEM_WRITE, bWritable);
	}

	PESection& PESection::Executable(bool bExecutable)
	{
		return setFlag(IMAGE_SCN_MEM_EXECUTE, bExecutable);
	}

	PESection& PESection::Shared(bool bShared)
	{
		return setFlag(IMAGE_SCN_MEM_SHARED, bShared);
	}

	PESection& PESection::Discardable(bool bDiscardable)
	{
		return setFlag(IMAGE_SCN_MEM_DISCARDABLE, bDiscardable);
	}

	// Returns  Attributes of the Section
	bool PESection::Readable()
	{
		return (m_SectionHeader.Characteristics & IMAGE_SCN_MEM_READ) NOT_EQUAL_TO 0;
	}
	
	bool PESection::Writable()
	{
		return (m_SectionHeader.Characteristics & IMAGE_SCN_MEM_WRITE) NOT_EQUAL_TO 0;
	}

	bool PESection::Executable()
	{
		return (m_SectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) NOT_EQUAL_TO 0;
	}

	bool PESection::Shared()
	{
		return (m_SectionHeader.Characteristics & IMAGE_SCN_MEM_SHARED) NOT_EQUAL_TO 0;
	}

	bool PESection::Discardable()
	{
		return (m_SectionHeader.Characteristics & IMAGE_SCN_MEM_DISCARDABLE) NOT_EQUAL_TO 0;
	}

	// Returns true if Section has no raw data
	bool PESection::empty() const
	{
		//If virtual memory is mapped, check raw data length (m_iOldSize)
		if (m_iOldSize NOT_EQUAL_TO static_cast<size_t>(-1))
			return m_iOldSize;
		else
			return m_sRawData.empty();
	}

	// Return raw section data from File image
	std::string& PESection::getRawData()
	{
		unmapVirtual();
		return m_sRawData;
	}

	const std::string& PESection::getRawData() const
	{
		unmapVirtual();
		return m_sRawData;
	}

	// Returns mapped virtual section data
	std::string& PESection::getVirtualData(uint32_t iSectionAlignment)
	{
		mapVirtual(iSectionAlignment);
		return m_sRawData;
	}

	const std::string& PESection::getVirtualData(uint32_t iSectionAlignment) const
	{
		mapVirtual(iSectionAlignment);
		return m_sRawData;
	}

	// Returns Section virtual size
	uint32_t PESection::getVirtualSize() const
	{
		return m_SectionHeader.Misc.VirtualSize;
	}

	// Returns Section virtual address, RVA
	uint32_t PESection::getVirtualAddress() const
	{
		return m_SectionHeader.VirtualAddress;
	}

	// Returns Size of Raw Data
	uint32_t PESection::getSizeOfRawData() const
	{
		return m_SectionHeader.SizeOfRawData;
	}

	// Returns pointer to Raw Section Data in PE File
	uint32_t PESection::getPointerToRawData() const
	{
		return m_SectionHeader.PointerToRawData;
	}

	// Returns Section Characteristics
	uint32_t PESection::getCharacteristics() const
	{
		return m_SectionHeader.Characteristics;
	}

	// Returns Raw Image Section Header
	Image_Section_Header& PESection::getRawHeader()
	{
		return m_SectionHeader;
	}

	const Image_Section_Header& PESection::getRawHeader() const
	{
		return m_SectionHeader;
	}

	// Calculate aligned virtual Section Size
	uint32_t PESection::getAlignedVirtualSize(uint32_t iSectionAlignment) const
	{
		if (getSizeOfRawData())
		{
			if (NOT getVirtualSize())
			{
				// If Section virtual size id zero,
				// Set the aligned Virtual Size of the Section to that of the aligned Raw Size.
				return PEUtils::alignUp(getSizeOfRawData(), iSectionAlignment);
			}
		}

		return PEUtils::alignUp(getVirtualSize(), iSectionAlignment);
	}

	// Calculate aligned Raw Section Size
	uint32_t PESection::getAlignedRawSize(uint32_t iFileAlignment) const
	{
		if (getSizeOfRawData())
		{
			return PEUtils::alignUp(getSizeOfRawData(), iFileAlignment);
		}
		else
			return 0;
	}

	// Set the Size of Raw Section
	void PESection::setSizeOfRawData(uint32_t iSizeOfRawData)
	{
		m_SectionHeader.SizeOfRawData = iSizeOfRawData;
	}

	// Sets pointer to Section Raw Data
	void PESection::setPointerToRawData(uint32_t iPointerToRawData)
	{
		m_SectionHeader.PointerToRawData = iPointerToRawData;
	}

	// Sets Section Characteristics
	void PESection::setCharacteristics(uint32_t iCharacteristics)
	{
		m_SectionHeader.Characteristics = iCharacteristics;
	}

	// Sets Raw Section Data from File Image
	void PESection::setRawData(const std::string& sData)
	{
		m_iOldSize = static_cast<size_t>(-1);
		m_sRawData = sData;
	}

	// Sets Section Virtual Size (doesn't set internal aligned virtual size, changes only header value)
	// Better use PEBase::setSectionVirtualSize
	void PESection::setVirtualSize(uint32_t iVirtualSize)
	{
		m_SectionHeader.Misc.VirtualSize = iVirtualSize;
	}

	// Sets Section Virtual Address
	void PESection::setVirtualAddress(uint32_t iVirtualAddress)
	{
		m_SectionHeader.VirtualAddress = iVirtualAddress;
	}

	void PESection::mapVirtual(uint32_t iSectionAlignement) const
	{
		uint32_t iAlignedVirtualSize = getAlignedVirtualSize(iSectionAlignement);
		if (m_iOldSize == static_cast<size_t>(-1) && iAlignedVirtualSize && iAlignedVirtualSize > m_sRawData.length())
		{
			m_iOldSize = m_sRawData.length();
			m_sRawData.resize(iAlignedVirtualSize, 0);
		}
	}

	// Unmaps Virtual Section Data
	void PESection::unmapVirtual() const
	{
		if (m_iOldSize NOT_EQUAL_TO static_cast<size_t>(-1))
		{
			m_sRawData.resize(m_iOldSize, 0);
			m_iOldSize = static_cast<size_t>(-1);
		}
	}

	// Set Flag(Attribute of Section)
	PESection& PESection::setFlag(uint32_t iFlag, bool bSetFlag)
	{
		if (bSetFlag)
			m_SectionHeader.Characteristics |= iFlag;
		else
			m_SectionHeader.Characteristics &= ~iFlag;

		return *this;
	}

	PESection_By_Raw_Offset::PESection_By_Raw_Offset(uint32_t iFileOffset)
		: m_iOffset(iFileOffset)
	{
	}

	bool PESection_By_Raw_Offset::operator()(const PESection& peSection) const
	{
		return (	m_iOffset >= peSection.getPointerToRawData()
					&&
					m_iOffset < peSection.getPointerToRawData() + peSection.getSizeOfRawData()
				);
	}
}