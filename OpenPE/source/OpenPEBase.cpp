#include "OpenPEBase.h"
#include "OpenPEException.h"
#include "OpenPEUtils.h"
#include <algorithm>

#define SAVE_ISTREAM_STATE(__iFileStream__) \
	std::ios_base::iostate iState = __iFileStream__.exceptions(); \
	std::streamoff oldStreamOffset = __iFileStream__.tellg(); \

#define RESTORE_ISTREAM_STATE(__iFileStream__) \
	__iFileStream__.exceptions(iState); \
	__iFileStream__.seekg(oldStreamOffset); \
	__iFileStream__.clear(); \

#define THROW_PEEXCEPTION(__stringDescription__, __exceptionType__) \
	throw PEException(__stringDescription__, __exceptionType__); \

#define THROW_EXCEPTION_IF_BAD_FILESTREAM(__fileStream__, __stringDescription__, __exceptionType__) \
	if (__fileStream__.bad() || __fileStream__.eof() || __fileStream__.fail()) \
		throw PEException(__stringDescription__, __exceptionType__); \

namespace OpenPE
{
	PEBase::PEBase(std::istream& pFileStream, const PEIProperties& pProperties, bool bReadDebugRawData /*= true*/)
	{
		m_pProperties = pProperties.duplicate().release();

		SAVE_ISTREAM_STATE(pFileStream);
		try
		{
			pFileStream.exceptions(std::ios::goodbit);

			// Reads & checks DOS header
			readDOSHeader(pFileStream);

			// Reads & checks PE Headers/Sections/Data
			readPE(pFileStream, bReadDebugRawData);
		}
		catch (const std::exception&)
		{
			// If something went wrong, restore the istream
			RESTORE_ISTREAM_STATE(pFileStream);

			// Rethrow the exception
			throw;
		}
		RESTORE_ISTREAM_STATE(pFileStream);
	}

	PEBase::PEBase(const PEBase& pe)
		: m_DOSHeader(pe.m_DOSHeader)
		, m_sRichOverlay(pe.m_sRichOverlay)
		, m_vSections(pe.m_vSections)
		, m_bHasOverlay(pe.m_bHasOverlay)
		, m_sFullHeadersData(pe.m_sFullHeadersData)
		//, m_DebugData(pe.m_DebugData)
		, m_pProperties(0)
	{
		m_pProperties = pe.m_pProperties->duplicate().release();
	}

	PEBase& PEBase::operator=(const PEBase& pe)
	{
		m_DOSHeader = pe.m_DOSHeader;

		delete m_pProperties;
		m_pProperties = pe.m_pProperties->duplicate().release();

		return *this;
	}

	// Returns the PE type (PE or PE+) from PEType enumeration of this Image
	PEType PEBase::getPEType(std::istream& pFileStream)
	{
		Image_Dos			_dosHeader;
		Image_NT_Headers32	_ntHeader;

		SAVE_ISTREAM_STATE(pFileStream);
		{
			try
			{
				// Read DOS header
				pFileStream.exceptions(std::ios::goodbit);
				readDOSHeader(pFileStream, _dosHeader);

				// Seek to the NT headers start
				pFileStream.seekg(_dosHeader.PointerToPEHeader);
				THROW_EXCEPTION_IF_BAD_FILESTREAM(pFileStream, "Cannot reach Image NT headers.", PEException::PEEXCEPTION_IMAGE_NT_HEADERS_NOT_FOUND);

				// Read NT headers (we are reading 32-bit version, since there is no significant difference between its 64-bit counterpart).
				pFileStream.read(reinterpret_cast<char*>(&_ntHeader), sizeof(Image_NT_Headers32)-(sizeof(Image_Data_Directory)* IMAGE_NUMBER_OF_DATA_DIRECTORY_ENTRIES));
				THROW_EXCEPTION_IF_BAD_FILESTREAM(pFileStream, "Error reading Image NT headers.", PEException::PEEXCEPTION_ERROR_READING_IMAGE_NT_HEADERS);

				// Confirm the signature of NT header, 'PE'
				if (_ntHeader.FileHeader.Signature NOT_EQUAL_TO 0x4550)
					THROW_PEEXCEPTION("Invalid NT signature.", PEException::PEEXCEPTION_INCORRECT_PE_SIGNATURE);

				// Check for NT headers Magic
				if (_ntHeader.OptionalHeader.Magic NOT_EQUAL_TO IMAGE_NT_OPTIONAL_HDR32_MAGIC
					&&
					_ntHeader.OptionalHeader.Magic NOT_EQUAL_TO IMAGE_NT_OPTIONAL_HDR64_MAGIC
				)
					THROW_PEEXCEPTION("Invalid NT signature.", PEException::PEEXCEPTION_INCORRECT_PE_SIGNATURE);
			}
			catch (const std::exception&)
			{
				// If something went wrong, restore the istream
				RESTORE_ISTREAM_STATE(pFileStream);

				// Rethrow the exception
				throw;
			}
		}
		RESTORE_ISTREAM_STATE(pFileStream);

		// Determine PE type & return it
		return _ntHeader.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? PEType_64 : PEType_32;
	}

	// Returns the PE type (PE or PE+) from PEType enumeration of this Image
	PEType PEBase::getPEType() const
	{
		return m_pProperties->getPEType();
	}

	// Returns true if Image has an Overlay
	bool PEBase::hasOverlay() const
	{
		return m_bHasOverlay;
	}

	// Reads & checks DOS header
	void PEBase::readDOSHeader(std::istream& pFileStream, Image_Dos& _dosHeader)
	{
		// Check stream flags
		THROW_EXCEPTION_IF_BAD_FILESTREAM(pFileStream, "PE File stream is bad or closed.", PEException::PEEXCEPTION_BAD_PE_FILE);

		// Read DOS header & check istream
		pFileStream.read(reinterpret_cast<char*>(&_dosHeader), sizeof(Image_Dos));
		THROW_EXCEPTION_IF_BAD_FILESTREAM(pFileStream, "Unable to read DOS header.", PEException::PEEXCEPTION_BAD_DOS_HEADER);

		// Check DOS Magic - 'MZ'
		if (_dosHeader.Signature NOT_EQUAL_TO 0x5a4d)
			THROW_PEEXCEPTION("Incorrect Image Dos header signature.", PEException::PEEXCEPTION_INCORRECT_PE_SIGNATURE);
	}

	// Reads DOS headers from istream
	void PEBase::readDOSHeader(std::istream& pFileStream)
	{
		readDOSHeader(pFileStream, m_DOSHeader);
	}

	// Reads & checks PE Headers/Sections/Data
	void PEBase::readPE(std::istream& pFileStream, bool bReadDebugRawData)
	{
		// Get the File size
		std::streamoff iFileSize = PEUtils::getFileSize(pFileStream);

		// Check if the PE header is DWORD-aligned
		if (m_DOSHeader.PointerToPEHeader % sizeof(uint32_t) NOT_EQUAL_TO 0)
			throw PEException("PE header is not DWord aligned", PEException::PEEXCEPTION_BAD_DOS_HEADER);

		// Seek to the NT Headers
		pFileStream.seekg(m_DOSHeader.PointerToPEHeader);
		THROW_EXCEPTION_IF_BAD_FILESTREAM(pFileStream, "Cannot reach NT Headers.", PEException::PEEXCEPTION_IMAGE_NT_HEADERS_NOT_FOUND);

		// read the NT Headers
		pFileStream.read(	getNTHeadersPtr(), 
							get_sizeofNTHeader() - sizeof(Image_Data_Directory) * IMAGE_NUMBER_OF_DATA_DIRECTORY_ENTRIES
						);
		THROW_EXCEPTION_IF_BAD_FILESTREAM(pFileStream, "Cannot read NT Headers.", PEException::PEEXCEPTION_ERROR_READING_IMAGE_NT_HEADERS);

		// Check PE Signature, 'PE'
		if (getPESignature() NOT_EQUAL_TO 0x4550)
			THROW_PEEXCEPTION("Invalid PE Signature", PEException::PEEXCEPTION_INCORRECT_PE_SIGNATURE);

		// Check number of Directories
		uint32_t iNumberOfRVAsAndSizes = getNumberOfRVAsAndSizes();
		if (iNumberOfRVAsAndSizes > IMAGE_NUMBER_OF_DATA_DIRECTORY_ENTRIES)
			setNumberOfRVAsAndSizes(IMAGE_NUMBER_OF_DATA_DIRECTORY_ENTRIES);

		if (iNumberOfRVAsAndSizes > 0)
		{
			// Read Directory Headers, if any
			pFileStream.read(	getNTHeadersPtr() + (get_sizeofNTHeader() - sizeof(Image_Data_Directory)* IMAGE_NUMBER_OF_DATA_DIRECTORY_ENTRIES),
								sizeof(Image_Data_Directory) * getNumberOfRVAsAndSizes()
							);
			THROW_EXCEPTION_IF_BAD_FILESTREAM(pFileStream, "Unable to read DATA_DIRECTORY headers.", PEException::PEEXCEPTION_ERROR_READING_DATA_DIRECTORIES);
		}

		// Check section numbers
		// Images with zero section number are accepted
		if (getNumberOfSections() > MAXIMUM_NUMBER_OF_SECTIONS)
			THROW_PEEXCEPTION("Incorrect number of sections.", PEException::PEEXCEPTION_TOO_MANY_SECTIONS);

		// Check PE magic
		if (getPEMagic() != getNeededMagic())
			THROW_PEEXCEPTION("Incorrect PE Magic.", PEException::PEEXCEPTION_INCORRECT_PE_SIGNATURE);

		// Check Section alignment
		if (NOT PEUtils::isPowerOf2(getSectionAlignment()))
			THROW_PEEXCEPTION("Incorrect Section alignment.", PEException::PEEXCEPTION_INCORRECT_SECTION_ALIGNMENT);

		// Check File alignment
		if (NOT PEUtils::isPowerOf2(getFileAlignment()))
			THROW_PEEXCEPTION("Incorrect File alignment.", PEException::PEEXCEPTION_INCORRECT_FILE_ALIGNMENT);

		if (getFileAlignment() NOT_EQUAL_TO getSectionAlignment()
			&&
			(	getFileAlignment() < MINIMUM_FILE_ALIGNMENT
				||
				getFileAlignment() > getSectionAlignment()
			)
		)
			THROW_PEEXCEPTION("Incorrect File & Section alignments", PEException::PEEXCEPTION_INCORRECT_FILE_ALIGNMENT);

		// Check size of Image
		if (PEUtils::alignUp(getSizeOfImage(), getSectionAlignment()) == 0)
			THROW_PEEXCEPTION("Incorrect size of Image", PEException::PEEXCEPTION_INCORRECT_SIZE_OF_IMAGE);

		// Read rich data overlay / DOS stub (if any)
		if (static_cast<uint32_t>(m_DOSHeader.PointerToPEHeader) > sizeof(Image_Dos))
		{
			m_sRichOverlay.resize(m_DOSHeader.PointerToPEHeader - sizeof(Image_Dos));
			pFileStream.seekg(sizeof(Image_Dos));
			pFileStream.read(&m_sRichOverlay[0], m_DOSHeader.PointerToPEHeader - sizeof(Image_Dos));
			THROW_EXCEPTION_IF_BAD_FILESTREAM(pFileStream, "Error reading 'Rich' & 'DOS' stub overlay", PEException::PEEXCEPTION_ERROR_READING_DOS_OVERLAY);
		}

		// Calculate first section raw position
		// Sum is safe.
		uint32_t iFirstSection = m_DOSHeader.PointerToPEHeader + get_sizeOfOptionalHeader() + sizeof(Image_COFF_FileHeader);
		if (getNumberOfSections() > 0)
		{
			// Gto the 1st Section
			pFileStream.seekg(iFirstSection);
			THROW_EXCEPTION_IF_BAD_FILESTREAM(pFileStream, "Cannot reach Section Header.", PEException::PEEXCEPTION_IMAGE_SECTION_HEADER_NOT_FOUND);
		}

		// Read All Sections
		uint32_t iLastRawSize = 0;
		for (int32_t i = 0; i < getNumberOfSections(); i++)
		{
			PESection peSection;

			// Read Section Header
			pFileStream.read(reinterpret_cast<char*>(&peSection.getRawHeader()), sizeof(Image_Section_Header));
			THROW_EXCEPTION_IF_BAD_FILESTREAM(pFileStream, "Error reading Section Header", PEException::PEEXCEPTION_IMAGE_SECTION_ERROR_READING_HEADER);

			// Save next Section Header offset
			std::streamoff iNextOffset = pFileStream.tellg();

			// Check Section Virtual & Raw Sizes
			THROW_EXCEPTION_IF_BAD_FILESTREAM(pFileStream, "Physical & Virtual Sizes of a Section cannot be 0 at the same time.", PEException::PEEXCEPTION_IMAGE_SECTION_ZERO_SIZES);

			// Check for adequate Section values
			if (	NOT PEUtils::isSumSafe(peSection.getVirtualAddress(), peSection.getVirtualSize())
					||
					NOT peSection.getVirtualSize() > PEUtils::TWO_GB
					||
					NOT PEUtils::isSumSafe(peSection.getPointerToRawData(), peSection.getSizeOfRawData())
					||
					NOT peSection.getSizeOfRawData() > PEUtils::TWO_GB
			)
				THROW_PEEXCEPTION("Incorrect Section addresses or Sizes", PEException::PEEXCEPTION_IMAGE_SECTION_INCORRECT_ADDRESS_OR_SIZES);

			if (peSection.getSizeOfRawData() != 0)
			{
				// If Section has Raw Data

				// If Section Raw Data is greater than Virtual, FIX IT !!!
				iLastRawSize = peSection.getSizeOfRawData();
				if (PEUtils::alignUp(peSection.getSizeOfRawData(), getFileAlignment()) > PEUtils::alignUp(peSection.getVirtualSize(), getSectionAlignment()))
					peSection.setSizeOfRawData(peSection.getVirtualSize());

				// Check Virtual & Raw Section Sizes & Addresses
				if (	(	peSection.getVirtualAddress() + PEUtils::alignUp(peSection.getVirtualSize(), getSectionAlignment())
							> 
							PEUtils::alignUp(getSizeOfImage(), getSectionAlignment())
						)
						||
						PEUtils::alignDown(peSection.getPointerToRawData(), getFileAlignment()) + peSection.getSizeOfRawData() > static_cast<uint32_t>(iFileSize)
				){
					THROW_PEEXCEPTION("Incorrect Section address or Size.", PEException::PEEXCEPTION_IMAGE_SECTION_INCORRECT_ADDRESS_OR_SIZES);
				}

				// Seek to Section raw Data
				pFileStream.seekg(PEUtils::alignDown(peSection.getPointerToRawData(), getFileAlignment()));
				THROW_EXCEPTION_IF_BAD_FILESTREAM(pFileStream, "Cannot reach Section Data.", PEException::PEEXCEPTION_IMAGE_SECTION_DATA_NOT_FOUND);

				// Read Section Raw Data
				peSection.getRawData().resize(peSection.getSizeOfRawData());
				pFileStream.read(&peSection.getRawData()[0], peSection.getSizeOfRawData());
				THROW_EXCEPTION_IF_BAD_FILESTREAM(pFileStream, "Error reading Section Data.", PEException::PEEXCEPTION_IMAGE_SECTION_ERROR_READING_SECTION_DATA);
			}

			// Check Virtual address & size of Section
			if (peSection.getVirtualAddress() + peSection.getAlignedVirtualSize(getSectionAlignment()) > PEUtils::alignUp(getSizeOfImage(), getSectionAlignment()))
			{
				THROW_PEEXCEPTION("Incorrect Section address or Size.", PEException::PEEXCEPTION_IMAGE_SECTION_INCORRECT_ADDRESS_OR_SIZES);
			}

			// Save Section
			m_vSections.push_back(peSection);

			// Seek to the next Section header
			pFileStream.seekg(iNextOffset);
		}

		// Check size of Headers: SizeOfHeaders can't be greater than first Sectiopn's VA
		if (NOT m_vSections.empty() && getSizeOfHeaders() > m_vSections.front().getVirtualAddress())
		{
			THROW_PEEXCEPTION("Incorrect Size of Headers.", PEException::PEEXCEPTION_INCORRECT_SIZE_OF_HEADERS);
		}

		// If Image has more than 2 Sections
		if (m_vSections.size() > 2)
		{
			// Check each Section's Virtual Size
			for (SECTION_LIST::iterator i = m_vSections.begin() + 1; i != m_vSections.end(); i++)
			{
				PESection& peSection = *i;
				PESection& pePrevSection = *(i-1);
				if(peSection.getVirtualAddress() != pePrevSection.getVirtualAddress() + pePrevSection.getAlignedVirtualSize(getSectionAlignment()))
				{
					THROW_PEEXCEPTION("Section Table is incorrect.", PEException::PEEXCEPTION_IMAGE_SECTION_TABLE_INCORRECT);
				}
			}
		}

		// Check if Image has an overlay at the end of the file
		m_bHasOverlay = NOT m_vSections.empty() && iFileSize > static_cast<std::streamoff>(m_vSections.back().getPointerToRawData() + iLastRawSize);
		{
			// Additionally, read data from the beginning of the stream to size of headers.
			pFileStream.seekg(0);
			uint32_t iSizeOfHeaders = std::min<uint32_t>(getSizeOfHeaders(), static_cast<uint32_t>(iFileSize));

			if (NOT m_vSections.empty())
			{
				for (SECTION_LIST::iterator i = m_vSections.begin(); i != m_vSections.end(); ++i)
				{
					PESection& peSection = *i;
					if (NOT peSection.empty())
					{
						iSizeOfHeaders = std::min<uint32_t>(getSizeOfHeaders(), peSection.getPointerToRawData());
						break;
					}
				}
			}

			m_sFullHeadersData.resize(iSizeOfHeaders);
			pFileStream.read(&m_sFullHeadersData[0], iSizeOfHeaders);
			THROW_EXCEPTION_IF_BAD_FILESTREAM(pFileStream, "Error reading file.", PEException::PEEXCEPTION_ERROR_READING_FILE);
		}

		// Moreover, if there's Debug Directory, read its Raw Data for some debug info types
		while (bReadDebugRawData && hasDebug())
		{
			try
			{
				// Check the length in b ytes of the Section containing the Debug Directory
			}
			catch (PEException&)
			{
				// Don't throw any Exception here if Debug Info is corrupted or incorrect
				break;
			}
			catch (std::bad_alloc&)
			{
				// Don't throw any Exception here if Debug Info is corrupted or incorrect
				break;
			}
		}
	}

	// Returns 'true' if Directory exists
	bool PEBase::directoryExists(uint32_t iDirectoryID) const
	{
		return m_pProperties->directoryExists(iDirectoryID);
	}

	// Removes specified Directory
	void PEBase::removeDirectory(uint32_t iDirectoryID)
	{
		// TODO
	}

	// Returns Directory RVA
	uint32_t PEBase::getDirectoryRVA(uint32_t iDirectoryID) const
	{
		return m_pProperties->getDirectoryRVA(iDirectoryID);
	}

	// Returns Directory Size
	uint32_t PEBase::getDirectorySize(uint32_t iDirectoryID) const
	{
		return m_pProperties->getDirectorySize(iDirectoryID);
	}

	// Sets Directory RVA (just a value in PE Header, no movement occurs)
	void PEBase::setDirectoryRVA(uint32_t iDirectoryID, uint32_t iRVA)
	{
		// TODO
	}

	// Sets Directory Size (just a value in PE Header, no movement occurs)
	void PEBase::setDirectorySize(uint32_t iDirectoryID, uint32_t iRVA)
	{
		// TODO
	}

	// Returns 'true' if Image has Import Directory
	bool PEBase::hasImports() const
	{
		return directoryExists(IMAGE_DIRECTORY_ENTRY_IMPORT);
	}

	// Returns 'true' if Image has Export Directory
	bool PEBase::hasExports() const
	{
		return directoryExists(IMAGE_DIRECTORY_ENTRY_EXPORT);
	}

	// Returns 'true' if Image has Resources Directory
	bool PEBase::hasResources() const
	{
		return directoryExists(IMAGE_DIRECTORY_ENTRY_RESOURCE);
	}

	// Returns 'true' if Image has Security Directory
	bool PEBase::hasSecurity() const
	{
		return directoryExists(IMAGE_DIRECTORY_ENTRY_SECURITY);
	}

	// Returns 'true' if Image has Relocations
	bool PEBase::hasReloc() const
	{
		return directoryExists(IMAGE_DIRECTORY_ENTRY_BASERELOC) && NOT(getCharacteristics() & IMAGE_FILE_RELOCS_STRIPPED);
	}

	// Returns 'true' if Image has TLS Directory
	bool PEBase::hasTLS() const
	{
		return directoryExists(IMAGE_DIRECTORY_ENTRY_TLS);
	}

	// Returns 'true' if Image has Config Directory
	bool PEBase::hasConfig() const
	{
		return directoryExists(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
	}

	// Returns 'true' if Image has Bound Import Directory
	bool PEBase::hasBoundImport() const
	{
		return directoryExists(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT);
	}

	// Returns 'true' if Image has Delayed Import Directory
	bool PEBase::hasDelayImport() const
	{
		return directoryExists(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
	}

	// Returns 'true' if Image has COM Directory
	bool PEBase::isDotNet() const
	{
		return directoryExists(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
	}

	// Returns 'true' if Image has Exception Directory
	bool PEBase::hasExceptionDirectory() const
	{
		return directoryExists(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
	}

	// Returns 'true' if Image has Debug Directory
	bool PEBase::hasDebug() const
	{
		return directoryExists(IMAGE_DIRECTORY_ENTRY_DEBUG);
	}

	// Returns Subsystem
	uint16_t PEBase::getSubsystem() const
	{
		return m_pProperties->getSubsystem();
	}

	// Sets Subsystem value
	void PEBase::setSubsystem(uint16_t iSubsystem)
	{
		m_pProperties->setSubsystem(iSubsystem);
	}

	// Returns true if image has console subsystem
	bool PEBase::isConsole() const
	{
		return (getSubsystem() == IMAGE_SUBSYSTEM_WINDOWS_CUI);
	}

	// Returns true if image has GUI subsystem
	bool PEBase::isGui() const
	{
		return (getSubsystem() == IMAGE_SUBSYSTEM_WINDOWS_GUI);
	}

	char* PEBase::getNTHeadersPtr() const
	{
		return m_pProperties->getNTHeaderPtr();
	}

	// Returns sizeof() NT Headers
	uint32_t PEBase::get_sizeofNTHeader() const
	{
		return m_pProperties->get_sizeOfNTHeader();
	}

	// Returns sizeof() Optional Header
	uint32_t PEBase::get_sizeOfOptionalHeader() const
	{
		return m_pProperties->get_sizeOfOptionalHeader();
	}

	// Returns Size of Headers
	uint32_t PEBase::getSizeOfHeaders() const
	{
		return m_pProperties->getSizeOfHeaders();
	}

	// Returns Size of Optional Header
	uint32_t PEBase::getSizeOfOptionalHeader() const
	{
		return m_pProperties->getSizeOfOptionalHeader();
	}

	// Return the PE Signature
	uint32_t PEBase::getPESignature() const
	{
		return m_pProperties->getPESignature();
	}

	// Returns number of RVA's & Sizes (number of DATA_DIRECTORY entries)
	uint32_t PEBase::getNumberOfRVAsAndSizes() const
	{
		return m_pProperties->getNumberOfRVAsAndSizes();
	}

	// Sets number of RVA's & Sizes (number of DATA_DIRECTORY entries)
	void PEBase::setNumberOfRVAsAndSizes(uint32_t iNumberOfRVAsAndSizes)
	{
		m_pProperties->setNumberOfRVAsAndSizes(iNumberOfRVAsAndSizes);
	}

	// Returns PE characteristics
	uint16_t PEBase::getCharacteristics() const
	{
		return m_pProperties->getCharacteristics();
	}

	// Returns Checksum of PE file from Header
	uint32_t PEBase::getChecksum() const
	{
		return m_pProperties->getChecksum();
	}
	
	// Sets Checksum of PE file
	void PEBase::setChecksum(uint32_t iChecksum)
	{
		m_pProperties->setChecksum(iChecksum);
	}

	// Returns Number of Sections
	uint32_t PEBase::getNumberOfSections() const
	{
		return m_pProperties->getNumberOfSections();
	}

	// Returns Section from RVA inside it
	PESection& PEBase::getSectionFromRVA(uint32_t iRVA)
	{
		// Search for the Section
		for (SECTION_LIST::iterator itr = m_vSections.begin(); itr != m_vSections.end(); ++itr)
		{
			PESection& peSection = *itr;

			// Return section if found
			if (	iRVA >= peSection.getVirtualAddress()
					&&
					iRVA < peSection.getVirtualAddress() + peSection.getAlignedVirtualSize(getSectionAlignment())
			) {
				return peSection;
			}
		}
	}

	// Returns Section from RVA inside it
	const PESection& PEBase::getSectionFromRVA(uint32_t iRVA) const
	{
		// Search for the Section
		for (SECTION_LIST::const_iterator itr = m_vSections.begin(); itr != m_vSections.end(); ++itr)
		{
			const PESection& peSection = *itr;

			// Return section if found
			if (	iRVA >= peSection.getVirtualAddress()
					&&
					iRVA < peSection.getVirtualAddress() + peSection.getAlignedVirtualSize(getSectionAlignment())
			) {
				return peSection;
			}
		}
	}


	uint16_t PEBase::getPEMagic() const
	{
		return m_pProperties->getPEMagic();
	}

	uint16_t PEBase::getNeededMagic() const
	{
		return m_pProperties->getNeedeMagic();
	}

	// Returns Section alignment
	uint32_t PEBase::getSectionAlignment() const
	{
		return m_pProperties->getSectionAlignment();
	}

	// Returns File alignment
	uint32_t PEBase::getFileAlignment() const
	{
		return m_pProperties->getFileAlignment();
	}

	// Returns Image Sections
	SECTION_LIST& PEBase::getImageSectionList()
	{
		return m_vSections;
	}

	const SECTION_LIST& PEBase::getImageSectionList() const
	{
		return m_vSections;
	}

	// Returns Size of the Image
	uint32_t PEBase::getSizeOfImage() const
	{
		return m_pProperties->getSizeOfImage();
	}

	// Returns Image Entry Point
	uint32_t PEBase::getEntryPoint() const
	{
		return m_pProperties->getEntryPoint();
	}

	// Sets Image Entry Point (Just the value in PE Header)
	void PEBase::setEntryPoint(uint32_t iNewEntryPoint)
	{
		m_pProperties->setEntryPoint(iNewEntryPoint);
	}
	// Returns Image base for PE(32-bit) & PE+(64-bit) respectively
	uint32_t PEBase::getImageBase32() const
	{
		return m_pProperties->getImageBase32();
	}

	uint64_t PEBase::getImageBase64() const
	{
		return m_pProperties->getImageBase64();
	}

	// Virtual Address(VA) to Relative Virtual Address(RVA) convertion
	// for PE32 & PE64 respectively
	uint32_t PEBase::getVAToRVA(uint32_t VA, bool bBoundCheck /*= true*/) const
	{
		return m_pProperties->getVAToRVA(VA, bBoundCheck);
	}

	uint32_t PEBase::getVAToRVA(uint64_t VA, bool bBoundCheck /*= true*/) const
	{
		return m_pProperties->getVAToRVA(VA, bBoundCheck);
	}

	// Relative Virtual Address(RVA) to Virtual Address(VA) convertion
	// for PE32 & PE64 respectively
	uint32_t PEBase::getRVAToVA_32(uint32_t RVA) const
	{
		return m_pProperties->getRVAToVA_32(RVA);
	}

	void PEBase::getRVAToVA_32(uint32_t RVA, uint32_t& VA) const
	{
		VA = getRVAToVA_32(RVA);
	}

	uint32_t PEBase::getRVAToVA_64(uint32_t RVA) const
	{
		return m_pProperties->getRVAToVA_64(RVA);
	}

	void PEBase::getRVAToVA_64(uint32_t RVA, uint64_t& VA) const
	{
		VA = getRVAToVA_64(RVA);
	}

	// RVA to RAW File Offset convertion(4GB max)
	uint32_t PEBase::getRVAToFileOffset(uint32_t RVA) const
	{
		// Maybe, RVA is inside PE Headers
		if (RVA < getSizeOfHeaders())
			return RVA;

		const PESection& s = getSectionFromRVA(RVA);
		return s.getPointerToRawData() + RVA - s.getVirtualAddress();
	}

	//  RAW to RVAFile Offset convertion(4GB max)
	uint32_t PEBase::getFileOffsetToRVA(uint32_t iFileOffset) const
	{
		// Maybe, offset is inside PE headers
		if (iFileOffset < getSizeOfHeaders())
		{
			return iFileOffset;
		}

		const SECTION_LIST::const_iterator itr = getFileOffsetToSection(iFileOffset);
		return iFileOffset - (*itr).getPointerToRawData() + (*itr).getVirtualAddress();
	}

	SECTION_LIST::iterator PEBase::getFileOffsetToSection(uint32_t iFileOffset)
	{
		SECTION_LIST::iterator itr = std::find_if(m_vSections.begin(), m_vSections.end(), PESection_By_Raw_Offset(iFileOffset));
		if (itr != m_vSections.end())
		{
			throw PEException("No section found that accommodates the file offset", PEException::PEEXXEPTION_NO_SECTION_FOUND);
		}

		return itr;
	}

	SECTION_LIST::const_iterator PEBase::getFileOffsetToSection(uint32_t iFileOffset) const
	{
		SECTION_LIST::const_iterator itr = std::find_if(m_vSections.begin(), m_vSections.end(), PESection_By_Raw_Offset(iFileOffset));
		if (itr != m_vSections.end())
		{
			throw PEException("No section found that accommodates the file offset", PEException::PEEXXEPTION_NO_SECTION_FOUND);
		}

		return itr;
	}

	// RVA from Section Offset
	uint32_t PEBase::getRVAFromSectionOffset(const PESection& peSection, uint32_t iRawOffsetFromSectionStart)
	{
		return peSection.getVirtualAddress() + iRawOffsetFromSectionStart;
	}

	PEBase::~PEBase()
	{
		delete m_pProperties;
	}
}