#include "OpenPEImports.h"
#include "OpenPEPropertiesGeneric.h"

namespace OpenPE
{
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	PEImportedFunction::PEImportedFunction()
		: m_iHint(0)
		, m_iOrdinal(0)
		, m_iIAT_VA(0)
	{
		 
	}

	// Returns 'true' if imported function has 'Name' (& Hint)
	bool PEImportedFunction::hasName() const
	{
		return NOT m_sName.empty();
	}

	// Returns 'Name' of the function
	const std::string& PEImportedFunction::getName() const
	{
		return m_sName;
	}

	// Returns 'Hint'
	uint16_t PEImportedFunction::getHint() const
	{
		return m_iHint;
	}

	// Returns 'Ordinal' of the function
	uint16_t PEImportedFunction::getOrdinal() const
	{
		return m_iOrdinal;
	}

	// Returns IAT entry VA (usable if image has both IAT and original IAT and is bound)
	uint64_t PEImportedFunction::getIAT_VA() const
	{
		return m_iIAT_VA;
	}

	// Setters do not change everything inside image, they are used by PE class
	// You also can use them to rebuild image imports
	// Sets 'Name' of function
	void PEImportedFunction::setName(const std::string& sName)
	{
		m_sName = sName;
	}

	// Sets 'Hint'
	void PEImportedFunction::setHint(uint16_t iHint)
	{
		m_iHint = iHint;
	}

	// Sets 'Ordinal'
	void PEImportedFunction::setOrdinal(uint16_t iOrdinal)
	{
		m_iOrdinal = iOrdinal;
	}

	// Sets IAT entry VA (usable if image has both IAT and original IAT and is bound)
	void PEImportedFunction::setIAT_VA(uint64_t iVA)
	{
		m_iIAT_VA = iVA;
	}
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Default Constructor
	PEImportLibrary::PEImportLibrary()
		: m_iRVAToIAT(0)
		, m_iRVAToOriginalIAT(0)
		, m_iTimeStamp(0)
	{

	}

	// Returns 'Name' of the Library
	const std::string& PEImportLibrary::getName() const
	{
		return m_sName;
	}

	// Returns RVA to Import Address Table(IAT)
	uint32_t PEImportLibrary::getRVAToIAT() const
	{
		return m_iRVAToIAT;
	}

	// Returns RVA to Original Import Address Table(Original IAT) 
	uint32_t PEImportLibrary::getRVATOOriginalIAT() const
	{
		return m_iRVAToOriginalIAT;
	}

	// Returns TimeStamp
	uint32_t PEImportLibrary::getTimeStamp() const
	{
		return m_iTimeStamp;
	}

	// Returns 'Imported' function list
	const PEImportLibrary::IMPORTED_LIST& PEImportLibrary::getImportedFunctionList() const
	{
		return m_vImportedFunctionList;
	}

	// Setters do not change everything inside image, they are used by PE class
	// You also can use them to rebuild image imports
	// Sets 'Name' of the Library
	void PEImportLibrary::setName(const std::string& sName)
	{
		m_sName = sName;
	}

	// Sets RVA to Import Address Table(IAT)
	void PEImportLibrary::setRVAToIAT(uint32_t iRVAToIAT)
	{
		m_iRVAToIAT = iRVAToIAT;
	}

	// Sets RVA to Original Import Address Table(Original IAT) 
	void PEImportLibrary::setRVATOOriginalIAT(uint32_t iRVAToOriginalIAT)
	{
		m_iRVAToOriginalIAT = iRVAToOriginalIAT;
	}

	// Sets TimeStamp
	void PEImportLibrary::setTimeStamp(uint32_t iTimeStamp)
	{
		m_iTimeStamp = iTimeStamp;
	}

	// Adds 'Imported' function to list
	void PEImportLibrary::addImport(const PEImportedFunction& func)
	{
		m_vImportedFunctionList.push_back(func);
	}

	// Clears 'Imported' function list
	void PEImportLibrary::clearImports()
	{
		m_vImportedFunctionList.clear();
	}
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// If set_to_pe_headers = true, IMAGE_DIRECTORY_ENTRY_IMPORT entry will be reset
	// to new value after import rebuilding
	// If auto_zero_directory_entry_iat = true, IMAGE_DIRECTORY_ENTRY_IAT will be set to zero
	// IMAGE_DIRECTORY_ENTRY_IAT is used by loader to temporarily make section, where IMAGE_DIRECTORY_ENTRY_IAT RVA points, writeable
	// to be able to modify IAT thunks
	PEImportRebuilderSettings::PEImportRebuilderSettings(bool bSetToPEHeaders, bool bAutoZeroDirectoryList)
		: m_iOffsetFromSectionStart(0)
		, m_bBuildOriginalIAT(true)
		, m_bSaveIATAndOriginalIATRVAs(true)
		, m_bFillMissingOriginalIATs(false)
		, m_bSetToPEHeaders(bSetToPEHeaders)
		, m_bZeroDirectoryEntryIAT(bAutoZeroDirectoryList)
		, m_bRewriteIATAndOoriginalIATContents(false)
		, m_bAutoStripLastSection(true)
	{

	}

	// Returns offset from section start where import directory data will be placed
	uint32_t PEImportRebuilderSettings::getOffsetFromSectionStart() const
	{
		return m_iOffsetFromSectionStart;
	}

	// Returns true if Original import address table (IAT) will be rebuilt
	bool PEImportRebuilderSettings::canBuildOriginalIAT() const
	{
		return m_bBuildOriginalIAT;
	}

	// Returns true if Original import address and import address tables will not be rebuilt,
	// works only if import descriptor IAT (and orig.IAT, if present) RVAs are not zero
	bool PEImportRebuilderSettings::saveIATAndOriginalIATRVAs() const
	{
		return m_bSaveIATAndOriginalIATRVAs;
	}

	// Returns true if Original import address and import address tables contents will be rewritten
	// works only if import descriptor IAT (and orig.IAT, if present) RVAs are not zero
	// and save_iat_and_original_iat_rvas is true
	bool PEImportRebuilderSettings::rewriteIATAndOriginalIATContents() const
	{
		return m_bRewriteIATAndOoriginalIATContents;
	}

	// Returns true if original missing IATs will be rebuilt
	// (only if IATs are saved)
	bool PEImportRebuilderSettings::fillMissingOriginalIATs() const
	{
		return m_bFillMissingOriginalIATs;
	}

	// Returns true if PE headers should be updated automatically after rebuilding of imports
	bool PEImportRebuilderSettings::autoSetToPEHeaders() const
	{
		return m_bSetToPEHeaders;
	}

	// Returns true if IMAGE_DIRECTORY_ENTRY_IAT must be zeroed, works only if auto_set_to_pe_headers = true
	bool PEImportRebuilderSettings::zeroDirectoryEntryIAT() const
	{
		return m_bZeroDirectoryEntryIAT;
	}

	// Returns true if the last section should be stripped automatically, if imports are inside it
	bool PEImportRebuilderSettings::autoStripLastSectionEnabled() const
	{
		return m_bAutoStripLastSection;
	}

	// Sets offset from section start where import directory data will be placed
	void PEImportRebuilderSettings::setOffsetFromSectionStart(uint32_t iOffset)
	{
		m_iOffsetFromSectionStart = iOffset;
	}

	// Sets if Original import address table (IAT) will be rebuilt
	void PEImportRebuilderSettings::buildOriginalIAT(bool bEnable)
	{
		m_bBuildOriginalIAT = bEnable;
	}

	// Sets if Original import address and import address tables will not be rebuilt,
	// works only if import descriptor IAT (and orig.IAT, if present) RVAs are not zero
	// enable_rewrite_iat_and_original_iat_contents sets if Original import address and import address tables contents will be rewritten
	// works only if import descriptor IAT (and orig.IAT, if present) RVAs are not zero
	// and save_iat_and_original_iat_rvas is true
	void PEImportRebuilderSettings::saveIATAndOriginalIATRVAs(bool bEnable, bool bEnableRewriteIATAndOriginalIATContents)
	{
		m_bSaveIATAndOriginalIATRVAs = bEnable;
		if (m_bSaveIATAndOriginalIATRVAs)
		{
			m_bRewriteIATAndOoriginalIATContents = bEnableRewriteIATAndOriginalIATContents;
		}
		else
			m_bRewriteIATAndOoriginalIATContents = false;
	}

	// Sets if original missing IATs will be rebuilt
	// (only if IATs are saved)
	void PEImportRebuilderSettings::fillMissingOriginalIATs(bool bEnable)
	{
		m_bFillMissingOriginalIATs = bEnable;
	}
	
	// Sets if PE headers should be updated automatically after rebuilding of imports
	void PEImportRebuilderSettings::autoSetToPEHeaders(bool bEnable)
	{
		m_bSetToPEHeaders = bEnable;
	}

	// Sets if IMAGE_DIRECTORY_ENTRY_IAT must be zeroed, works only if auto_set_to_pe_headers = true
	void PEImportRebuilderSettings::zeroDirectoryEntryIAT(bool bEnable)
	{
		m_bZeroDirectoryEntryIAT = bEnable;
	}

	// Sets if the last section should be stripped automatically, if imports are inside it, default true
	void PEImportRebuilderSettings::enableAutoStripLastSection(bool bEnable)
	{
		m_bAutoStripLastSection = bEnable;
	}
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	const PEIMPORTED_FUNCTIONS_LIST	getImportedFunctionsList(const PEBase& peBase)
	{
		return (	peBase.getPEType() == PEType_32
					?
					getImportedFunctionsBase<PETypeClass32>(peBase)
					:
					getImportedFunctionsBase<PETypeClass64>(peBase)
			);
	}

	// Returns imported functions list with related libraries info
	template<typename PEClassType>
	const PEIMPORTED_FUNCTIONS_LIST	getImportedFunctionsBase(const PEBase& peBase)
	{
		PEIMPORTED_FUNCTIONS_LIST returnList;

		// If image has no imports, return empty array
		if (NOT peBase.hasImports())
		{
			return returnList;
		}

		unsigned long iCurrentDescriptorPosition = peBase.getDirectoryRVA(IMAGE_DIRECTORY_ENTRY_IMPORT);

		// Get first IMAGE_IMPORT_DESCRIPTOR
		IMAGE_IMPORT_DESCRIPTOR peImportDescriptor = peBase.getSectionDataFromRVA<IMAGE_IMPORT_DESCRIPTOR>(	iCurrentDescriptorPosition,
																											SECTION_DATA_VIRTUAL,
																											true);

		// Iterate them until we reach zero-element
		// We don't need to check correctness of this, because exception will be thrown
		// inside of loop if we go outsize of section
		while (peImportDescriptor.iName)
		{
			// Get imported library information
			PEImportLibrary peLibrary;

			unsigned long iMaxNameLength;

			// Get byte count that we have for library name
			if ((iMaxNameLength = peBase.getSectionDataLengthFromRVA(	peImportDescriptor.iName, 
																		peImportDescriptor.iName, 
																		SECTION_DATA_VIRTUAL,
																		true)
				) < 2
			) {
				throw PEException("Incorrect Import Directory.", PEException::PEEXCEPTION_INCORRECT_IMPORT_DIRECTORY);
			}

			// Get DLL name pointer
			const char* pDllName = peBase.getSectionDataFromRVA(peImportDescriptor.iName, SECTION_DATA_VIRTUAL, true);

			// Check for null-termination
			if (NOT PEUtils::isNullTerminated(pDllName, iMaxNameLength))
			{
				throw PEException("Incorrect Import Directory.", PEException::PEEXCEPTION_INCORRECT_IMPORT_DIRECTORY);
			}

			// Set Library Name
			peLibrary.setName(pDllName);

			// Set Library TimeStamp
			peLibrary.setTimeStamp(peImportDescriptor.iTimeStamp);

			// Set library RVA to IAT and original IAT
			peLibrary.setRVAToIAT(peImportDescriptor.iFirstThunk);
			peLibrary.setRVATOOriginalIAT(peImportDescriptor.iOriginalFirstThunk);

			// Get RVA to IAT (it must be filled by loader when loading PE)
			uint32_t iCurrentThunkRVA = peImportDescriptor.iFirstThunk;
			typename PEClassType::BaseSize importAddressTable = peBase.getSectionDataFromRVA<PETypeClass32::BaseSize>(	iCurrentThunkRVA,
																														SECTION_DATA_VIRTUAL,
																														true);
			
			// Get RVA to original IAT (lookup table), which must handle imported functions names
			// Some linkers leave this pointer zero-filled
			// Such image is valid, but it is not possible to restore imported functions names
			// afted image was loaded, because IAT becomes the only one table
			// containing both function names and function RVAs after loading
			uint32_t iCurrentOriginalThunkRVA = peImportDescriptor.iOriginalFirstThunk;
			typename PEClassType::BaseSize importLookUpTable = (iCurrentOriginalThunkRVA == 0) 
																	? 
																	importAddressTable
																	:
																	peBase.getSectionDataFromRVA<PETypeClass32::BaseSize>(	iCurrentOriginalThunkRVA,
																															SECTION_DATA_VIRTUAL,
 																															true);
			if (iCurrentOriginalThunkRVA == 0)
				iCurrentOriginalThunkRVA = iCurrentThunkRVA;

			// List all imported functions for current DLL
			if (importLookUpTable NOT_EQUAL_TO 0 && importAddressTable NOT_EQUAL_TO 0)
			{
				while (true)
				{
					// Imported Function Descriptor
					PEImportedFunction func;

					// Get VA from IAT
					typename PEClassType::BaseSize address = peBase.getSectionDataFromRVA<typename PEClassType::BaseSize>(	iCurrentThunkRVA,
																															SECTION_DATA_VIRTUAL,
																															true);
					// Move Pointer
					iCurrentThunkRVA += sizeof(typename PEClassType::BaseSize);

					// Jump to next DLL if we finished with this one
					if (NOT address)
					{
						break;
					}

					func.setIAT_VA(address);

					// Get VA from original IAT
					typename PEClassType::BaseSize lookup = peBase.getSectionDataFromRVA<typename PEClassType::BaseSize>(	iCurrentOriginalThunkRVA,
																															SECTION_DATA_VIRTUAL,
																															true);
					// Move Pointer
					iCurrentOriginalThunkRVA += sizeof(typename PEClassType::BaseSize);

					// Check if function is imported by ordinal
					if ((lookup & PEClassType::ImportSnapFlag) NOT_EQUAL_TO 0)
					{
						// Set function ordinal
						func.setOrdinal(static_cast<uint16_t>(lookup & 0xffff));
					}
					else
					{
						// Get byte count that we have for function name
						if (lookup > static_cast<uint32_t>(-1) - sizeof(uint16_t))
						{
							throw PEException("Incorrect Import Directory.", PEException::PEEXCEPTION_INCORRECT_IMPORT_DIRECTORY);
						}

						// Get maximum available length of function name
						if ((iMaxNameLength = peBase.getSectionDataLengthFromRVA(	static_cast<uint32_t>(lookup + sizeof(uint16_t)),
																					static_cast<uint32_t>(lookup + sizeof(uint16_t)), 
																					SECTION_DATA_VIRTUAL, 
																					true)) < 2)
						{
							throw PEException("Incorrect Import Directory.", PEException::PEEXCEPTION_INCORRECT_IMPORT_DIRECTORY);
						}

						// Get imported function name
						const char* pFuncName = peBase.getSectionDataFromRVA(	static_cast<uint32_t>(lookup + sizeof(uint16_t)),
																				SECTION_DATA_VIRTUAL, 
																				true);

						// Check for null-termination
						if (!PEUtils::isNullTerminated(pFuncName, iMaxNameLength))
							throw PEException("Incorrect Import Directory.", PEException::PEEXCEPTION_INCORRECT_IMPORT_DIRECTORY);

						// HINT in import table is ORDINAL in export table
						uint16_t iHint = peBase.getSectionDataFromRVA<uint16_t>(static_cast<uint32_t>(lookup), SECTION_DATA_VIRTUAL, true);

						//Save hint and name
						func.setName(pFuncName);
						func.setHint(iHint);
					}

					// Add function to list
					peLibrary.addImport(func);
				}
			}

			// Check possible overflow
			if (!PEUtils::isSumSafe(iCurrentDescriptorPosition, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
				throw PEException("Incorrect Import Directory.", PEException::PEEXCEPTION_INCORRECT_IMPORT_DIRECTORY);

			//Go to next library
			iCurrentDescriptorPosition += sizeof(IMAGE_IMPORT_DESCRIPTOR);
			peImportDescriptor = peBase.getSectionDataFromRVA<IMAGE_IMPORT_DESCRIPTOR>(iCurrentDescriptorPosition, SECTION_DATA_VIRTUAL, true);

			// Save import information
			returnList.push_back(peLibrary);
		}

		// Return resulting list
		return returnList;
	}

	// TODO - PEImportAdder
	//const PEImageDirectory rebuildImports(	PEBase& peBase,
	//										const PEIMPORTED_FUNCTIONS_LIST& imports,
	//										PESection& importSection,
	//										const PEImportRebuilderSettings& import_settings
	//) {
	//	return (	peBase.getPEType() == PEType_32
	//				?
	//				rebuildImportsBase<PETypeClass32>(peBase, imports, importSection, import_settings)
	//				:
	//				rebuildImportsBase<PETypeClass64>(peBase, imports, importSection, import_settings)
	//		);
	//}

	// TODO - PEImportAdder
	//template<typename PEClassType>
	//const PEImageDirectory rebuildImportsBase(	PEBase& pe,
	//											const PEIMPORTED_FUNCTIONS_LIST& imports,
	//											PESection& importSection,
	//											const PEImportRebuilderSettings& import_settings
	//) {
	//
	//}
}