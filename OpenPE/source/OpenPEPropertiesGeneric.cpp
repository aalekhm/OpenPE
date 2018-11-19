#include "OpenPEPropertiesGeneric.h"
#include "OpenPEException.h"
#include "OpenPEUtils.h"

namespace OpenPE
{
	// Constructor
	template<typename PEClassType>
	std::auto_ptr<PEIProperties> PEPropertiesGeneric<PEClassType>::duplicate() const
	{
		return std::auto_ptr<PEIProperties>(new PEPropertiesGeneric<PEClassType>(*this));
	}

	// Fills the PE Structures
	template<typename PEClassType>
	void PEPropertiesGeneric<PEClassType>::createPE(uint32_t iSectionAlignment, uint16_t iSubsystem)
	{
		memset(&m_NTHeader, 0, sizeof(m_NTHeader));

		m_NTHeader.FileHeader.Signature					= 0x4550; //"PE"
		m_NTHeader.FileHeader.Machine					= 0x14C; //i386
		m_NTHeader.FileHeader.SizeOfOptionalHeader		= sizeof(m_NTHeader.OptionalHeader);
		m_NTHeader.OptionalHeader.Magic					= PEClassType::ID;
		m_NTHeader.OptionalHeader.ImageBase				= 0x400000;
		m_NTHeader.OptionalHeader.SectionAlignment		= iSectionAlignment;
		m_NTHeader.OptionalHeader.FileAlignment			= 0x200;
		m_NTHeader.OptionalHeader.SizeOfHeaders			= 1024;
		m_NTHeader.OptionalHeader.Subsystem				= iSubsystem;
		m_NTHeader.OptionalHeader.SizeOfHeapReserve		= 0x100000;
		m_NTHeader.OptionalHeader.SizeOfHeapCommit		= 0x1000;
		m_NTHeader.OptionalHeader.SizeOfStackReserve	= 0x100000;
		m_NTHeader.OptionalHeader.SizeOfStackCommit		= 0x1000;
		m_NTHeader.OptionalHeader.NumberOfRVAAndSizes	= 0x10;
	}

	template<typename PEClassType>
	PEType PEPropertiesGeneric<PEClassType>::getPEType() const
	{
		return (PEClassType::ID == IMAGE_NT_OPTIONAL_HDR32_MAGIC) ? PEType_32 : PEType_64;
	}

	template<typename PEClassType>
	uint32_t PEPropertiesGeneric<PEClassType>::getImageBase32() const
	{
		return static_cast<uint32_t>(m_NTHeader.OptionalHeader.ImageBase);
	}

	template<typename PEClassType>
	uint64_t PEPropertiesGeneric<PEClassType>::getImageBase64() const
	{
		return static_cast<uint64_t>(m_NTHeader.OptionalHeader.ImageBase);
	}

	template<typename PEClassType>
	uint32_t PEPropertiesGeneric<PEClassType>::getEntryPoint() const
	{
		return m_NTHeader.OptionalHeader.AddressOfEntryPoint;
	}

	template<typename PEClassType>
	void PEPropertiesGeneric<PEClassType>::setEntryPoint(uint32_t iNewEntryPoint)
	{
		m_NTHeader.OptionalHeader.AddressOfEntryPoint = iNewEntryPoint;
	}

	template<typename PEClassType>
	uint32_t PEPropertiesGeneric<PEClassType>::getFileAlignment() const
	{
		return m_NTHeader.OptionalHeader.FileAlignment;
	}

	template<typename PEClassType>
	uint32_t PEPropertiesGeneric<PEClassType>::getSectionAlignment() const
	{
		return m_NTHeader.OptionalHeader.SectionAlignment;
	}

	template<typename PEClassType>
	uint32_t PEPropertiesGeneric<PEClassType>::getHeapSizeCommit32() const
	{
		return static_cast<uint32_t>(m_NTHeader.OptionalHeader.SizeOfHeapCommit);
	}

	template<typename PEClassType>
	uint64_t PEPropertiesGeneric<PEClassType>::getHeapSizeCommit64() const
	{
		return static_cast<uint64_t>(m_NTHeader.OptionalHeader.SizeOfHeapCommit);
	}

	template<typename PEClassType>
	uint32_t PEPropertiesGeneric<PEClassType>::getHeapSizeReserve32() const
	{
		return static_cast<uint32_t>(m_NTHeader.OptionalHeader.SizeOfHeapReserve);
	}

	template<typename PEClassType>
	uint64_t PEPropertiesGeneric<PEClassType>::getHeapSizeReserve64() const
	{
		return static_cast<uint64_t>(m_NTHeader.OptionalHeader.SizeOfHeapReserve);
	}

	template<typename PEClassType>
	uint32_t PEPropertiesGeneric<PEClassType>::getStackSizeCommit32() const
	{
		return static_cast<uint32_t>(m_NTHeader.OptionalHeader.SizeOfStackCommit);
	}

	template<typename PEClassType>
	uint64_t PEPropertiesGeneric<PEClassType>::getStackSizeCommit64() const
	{
		return static_cast<uint64_t>(m_NTHeader.OptionalHeader.SizeOfStackCommit);
	}

	template<typename PEClassType>
	uint32_t PEPropertiesGeneric<PEClassType>::getStackSizeReserve32() const
	{
		return static_cast<uint32_t>(m_NTHeader.OptionalHeader.SizeOfStackReserve);
	}

	template<typename PEClassType>
	uint64_t PEPropertiesGeneric<PEClassType>::getStackSizeReserve64() const
	{
		return static_cast<uint64_t>(m_NTHeader.OptionalHeader.SizeOfStackReserve);
	}

	template<typename PEClassType>
	uint32_t PEPropertiesGeneric<PEClassType>::getSizeOfImage() const
	{
		return m_NTHeader.OptionalHeader.SizeOfImage;
	}

	template<typename PEClassType>
	uint32_t PEPropertiesGeneric<PEClassType>::getNumberOfRVAsAndSizes() const
	{
		return m_NTHeader.OptionalHeader.NumberOfRVAAndSizes;
	}

	template<typename PEClassType>
	void PEPropertiesGeneric<PEClassType>::setNumberOfRVAsAndSizes(uint32_t iNumberOfRVAsAndSizes)
	{
		m_NTHeader.OptionalHeader.NumberOfRVAAndSizes = iNumberOfRVAsAndSizes;
	}

	template<typename PEClassType>
	uint32_t PEPropertiesGeneric<PEClassType>::getCharacteristics() const
	{
		return m_NTHeader.FileHeader.Characteristics;
	}

	template<typename PEClassType>
	uint32_t PEPropertiesGeneric<PEClassType>::getSizeOfHeaders() const
	{
		return m_NTHeader.OptionalHeader.SizeOfHeaders;
	}

	// Returns Subsystem
	template<typename PEClassType>
	uint16_t PEPropertiesGeneric<PEClassType>::getSubsystem() const
	{
		return m_NTHeader.OptionalHeader.Subsystem;
	}

	// Sets Subsystem value
	template<typename PEClassType>
	void PEPropertiesGeneric<PEClassType>::setSubsystem(uint16_t iSubsystem)
	{
		m_NTHeader.OptionalHeader.Subsystem = iSubsystem;
	}

	template<typename PEClassType>
	uint32_t PEPropertiesGeneric<PEClassType>::getSizeOfOptionalHeader() const
	{
		return m_NTHeader.FileHeader.SizeOfOptionalHeader;
	}

	template<typename PEClassType>
	uint16_t PEPropertiesGeneric<PEClassType>::getPESignature() const
	{
		return m_NTHeader.FileHeader.Signature;
	}

	template<typename PEClassType>
	uint16_t PEPropertiesGeneric<PEClassType>::getPEMagic() const
	{
		return m_NTHeader.OptionalHeader.Magic;
	}

	// Returns Checksum of PE file from header
	template<typename PEClassType>
	uint32_t PEPropertiesGeneric<PEClassType>::getChecksum() const
	{
		return m_NTHeader.OptionalHeader.Checksum;
	}

	// Sets Checksum of PE file
	template<typename PEClassType>
	void PEPropertiesGeneric<PEClassType>::setChecksum(uint32_t iChecksum)
	{
		m_NTHeader.OptionalHeader.Checksum = iChecksum;
	}

	template<typename PEClassType>
	uint32_t PEPropertiesGeneric<PEClassType>::getTimeDateStamp() const
	{
		return m_NTHeader.FileHeader.TimeDateStamp;
	}

	template<typename PEClassType>
	uint16_t PEPropertiesGeneric<PEClassType>::getMachine() const
	{
		return m_NTHeader.FileHeader.Machine;
	}

	template<typename PEClassType>
	uint16_t PEPropertiesGeneric<PEClassType>::getDLLCharacteristics() const
	{
		return m_NTHeader.OptionalHeader.DllCharacteristics;
	}

	template<typename PEClassType>
	uint16_t PEPropertiesGeneric<PEClassType>::getMinorOSVersion() const
	{
		return m_NTHeader.OptionalHeader.MinorOperatingSystemVersion;
	}

	template<typename PEClassType>
	uint16_t PEPropertiesGeneric<PEClassType>::getMajorOSVersion() const
	{
		return m_NTHeader.OptionalHeader.MajorOperatingSystemVersion;
	}

	template<typename PEClassType>
	uint16_t PEPropertiesGeneric<PEClassType>::getMinorSubsystem() const
	{
		return m_NTHeader.OptionalHeader.MajorSubsystemVersion;
	}

	template<typename PEClassType>
	uint16_t PEPropertiesGeneric<PEClassType>::getMajorSubsystem() const
	{
		return m_NTHeader.OptionalHeader.MajorSubsystemVersion;
	}

	template<typename PEClassType>
	bool PEPropertiesGeneric<PEClassType>::directoryExists(uint32_t iDirectoryID) const
	{
		return ((m_NTHeader.OptionalHeader.NumberOfRVAAndSizes - 1) >= iDirectoryID
				&&
				m_NTHeader.OptionalHeader.DataDirectory[iDirectoryID].RVA);
	}

	template<typename PEClassType>
	uint32_t PEPropertiesGeneric<PEClassType>::getDirectoryRVA(uint32_t iDirectoryID) const
	{
		//Check if directory exists
		if (NOT directoryExists(iDirectoryID))
			throw PEException("Specified directory does not exists.", PEException::PEEXCEPTION_DIRECTORY_DOESN_NOT_EXISTS);

		return m_NTHeader.OptionalHeader.DataDirectory[iDirectoryID].RVA;
	}

	template<typename PEClassType>
	uint32_t PEPropertiesGeneric<PEClassType>::getDirectorySize(uint32_t iDirectoryID) const
	{
		//Check if directory exists
		if (NOT directoryExists(iDirectoryID))
			throw PEException("Specified directory does not exists.", PEException::PEEXCEPTION_DIRECTORY_DOESN_NOT_EXISTS);

		return m_NTHeader.OptionalHeader.DataDirectory[iDirectoryID].Size;
	}

	// Virtual Address(VA) to Relative Virtual Address(RVA) convertion
	// for PE32 & PE64 respectively
	template<typename PEClassType>
	uint32_t PEPropertiesGeneric<PEClassType>::getVAToRVA(uint32_t VA, bool bBoundCheck /*= true*/) const
	{
		if (	bBoundCheck
				&&
				static_cast<uint32_t>(VA) - m_NTHeader.OptionalHeader.ImageBase > PEUtils::MAX_DWORD
		) {
			throw PEException("Incorrect Address Conversion", PEException::PEEXCEPTION_INCORRECT_ADDRESS_CONVERSION);
		}

		return static_cast<uint32_t>(VA - m_NTHeader.OptionalHeader.ImageBase);
	}

	// Relative Virtual Address (RVA) to Virtual Address (VA) convertions for PE32/PE64
	template<typename PEClassType>
	uint32_t PEPropertiesGeneric<PEClassType>::getVAToRVA(uint64_t VA, bool bBoundCheck /*= true*/) const
	{
		if(		bBoundCheck
				&&
				VA - m_NTHeader.OptionalHeader.ImageBase > PEUtils::MAX_DWORD
		) {
			throw PEException("Incorrect Address Conversion", PEException::PEEXCEPTION_INCORRECT_ADDRESS_CONVERSION);
		}

		return static_cast<uint32_t>(VA - m_NTHeader.OptionalHeader.ImageBase);
	}

	// Relative Virtual Address(RVA) to Virtual Address(VA) convertion
	// for PE32 & PE64 respectively
	template<typename PEClassType>
	uint32_t PEPropertiesGeneric<PEClassType>::getRVAToVA_32(uint32_t RVA) const
	{
		if (NOT PEUtils::isSumSafe(RVA, static_cast<uint32_t>(m_NTHeader.OptionalHeader.ImageBase)))
		{
			throw PEException("Incorrect Address Conversion", PEException::PEEXCEPTION_INCORRECT_ADDRESS_CONVERSION);
		}

		return static_cast<uint32_t>(RVA + m_NTHeader.OptionalHeader.ImageBase);
	}

	// Relative Virtual Address (RVA) to Virtual Address (VA) convertions for PE32/PE64
	template<typename PEClassType>
	uint32_t PEPropertiesGeneric<PEClassType>::getRVAToVA_64(uint32_t RVA) const
	{
		return static_cast<uint64_t>(RVA) + m_NTHeader.OptionalHeader.ImageBase;
	}

	template<typename PEClassType>
	uint16_t PEPropertiesGeneric<PEClassType>::getNumberOfSections() const
	{
		return m_NTHeader.FileHeader.NumberOfSections;
	}

	template<typename PEClassType>
	char* PEPropertiesGeneric<PEClassType>::getNTHeaderPtr()
	{
		return reinterpret_cast<char*>(&m_NTHeader);
	}

	template<typename PEClassType>
	const char* PEPropertiesGeneric<PEClassType>::getNTHeaderPtr() const
	{
		return reinterpret_cast<const char*>(&m_NTHeader);
	}

	template<typename PEClassType>
	uint32_t PEPropertiesGeneric<PEClassType>::get_sizeOfNTHeader() const
	{
		return sizeof(typename PEClassType::NTHeader);
	}

	template<typename PEClassType>
	uint32_t PEPropertiesGeneric<PEClassType>::get_sizeOfOptionalHeader() const
	{
		return sizeof(typename PEClassType::OptionalHeader);
	}

	template<typename PEClassType>
	uint32_t PEPropertiesGeneric<PEClassType>::getBaseOfCode() const
	{
		return m_NTHeader.OptionalHeader.BaseOfCode;
	}
	
	template<typename PEClassType>
	uint32_t PEPropertiesGeneric<PEClassType>::getNeedeMagic() const
	{
		return PEClassType::ID;
	}

	// Destructor
	template<typename PEClassType>
	PEPropertiesGeneric<PEClassType>::~PEPropertiesGeneric()
	{}

	// Explicit instantiation of the 2 class types.
	template class PEPropertiesGeneric<PETypeClass32>;
	template class PEPropertiesGeneric<PETypeClass64>;
}