#include "OpenPEExports.h"

namespace OpenPE
{
	// Default Constructor
	PEExportedFunction::PEExportedFunction()
		: m_iOrdinal(0)
		, m_iRVA(0)
		, m_bHasName(false)
		, m_iNameOrdinal(0)
		, m_bForwarded(false)
	{
	}

	// Returns ordinal of function (actually, ordinal = hint + ordinal base)
	uint16_t PEExportedFunction::getOrdinal() const
	{
		return m_iOrdinal;
	}

	// Returns RVA of function
	uint32_t PEExportedFunction::getRVA() const
	{
		return m_iRVA;
	}

	// Returns true if function has name and name ordinal
	bool PEExportedFunction::hasName() const
	{
		return m_bHasName;
	}

	// Returns name of function
	const std::string& PEExportedFunction::getName() const
	{
		return m_sName;
	}

	// Returns name ordinal of function
	uint16_t PEExportedFunction::getNameOrdinal() const
	{
		return m_iNameOrdinal;
	}

	// Returns true if function is forwarded to other library
	bool PEExportedFunction::isForwarded() const
	{
		return m_bForwarded;
	}

	// Returns the name of forwarded function
	const std::string& PEExportedFunction::getForwardedName() const
	{
		return m_sForwardedName;
	}

	// Sets ordinal of function
	void PEExportedFunction::setOrdinal(uint16_t iOrdinal)
	{
		m_iOrdinal = iOrdinal;
	}

	// Sets RVA of function
	void PEExportedFunction::setRVA(uint32_t iRVA)
	{
		m_iRVA = iRVA;
	}

	// Sets name of function (or clears it, if empty name is passed)
	void PEExportedFunction::setName(const std::string& sName)
	{
		m_sName = sName;
		m_bHasName = NOT sName.empty();
	}

	// Sets name ordinal
	void PEExportedFunction::setNameOrdinal(uint16_t iNameOrdinal)
	{
		m_iNameOrdinal = iNameOrdinal;
	}

	// Sets forwarded function name (or clears it, if empty name is passed)
	void PEExportedFunction::setForwardedName(const std::string& sName)
	{
		m_sForwardedName = sName;
		m_bForwarded = NOT sName.empty();
	}

	// Class representing export information
	// Default constructor
	PEExportInfo::PEExportInfo()
		: m_iCharacteristics(0)
		, m_iTimeStamp(0)
		, m_iMajorVersion(0)
		, m_iMinorVersion(0)
		, m_iOrdinalBase(0)
		, m_iNumberOfFunctions(0)
		, m_iNumberOfNames(0)
		, m_iAddressOfFunctions(0)
		, m_iAddressOfNames(0)
		, m_iAddressOfNameOrdinals(0)
	{
	}

	// Returns characteristics
	uint32_t PEExportInfo::getCharacteristics() const
	{
		return m_iCharacteristics;
	}

	// Returns TimeStamp
	uint32_t PEExportInfo::getTimeStamp() const
	{
		return m_iTimeStamp;
	}

	// Returns major version
	uint16_t PEExportInfo::getMajorVersion() const
	{
		return m_iMajorVersion;
	}
	
	// Returns minor version
	uint16_t PEExportInfo::getMinorVersion() const
	{
		return m_iMinorVersion;
	}

	// Returns DLL name
	const std::string& PEExportInfo::getName() const
	{
		return m_sName;
	}

	// Returns ordinal base
	uint32_t PEExportInfo::getOrdinalBase() const
	{
		return m_iOrdinalBase;
	}

	// Returns number of functions
	uint32_t PEExportInfo::getNumberOfFunctions() const
	{
		return m_iNumberOfFunctions;
	}

	// Returns number of function names
	uint32_t PEExportInfo::getNumberOfNames() const
	{
		return m_iNumberOfNames;
	}

	// Returns RVA of function address table
	uint32_t PEExportInfo::getRVAOfFunctions() const
	{
		return m_iAddressOfFunctions;
	}

	// Returns RVA of function name address table
	uint32_t PEExportInfo::getRVAOfNames() const
	{
		return m_iAddressOfNames;
	}

	// Returns RVA of name ordinals table
	uint32_t PEExportInfo::getRVAOfNameOrdinals() const
	{
		return m_iAddressOfNameOrdinals;
	}

	// Sets Characteristics
	void PEExportInfo::setCharacteristics(uint32_t	iCharacteristics)
	{
		m_iCharacteristics = iCharacteristics;
	}

	// Sets timestamp
	void PEExportInfo::setTimeStamp(uint32_t iTimeStamp)
	{
		m_iTimeStamp = iTimeStamp;
	}

	// Sets major version
	void PEExportInfo::setMajorVersion(uint16_t iMajorVersion)
	{
		m_iMajorVersion = iMajorVersion;
	}

	// Sets minor version
	void PEExportInfo::setMinorVersion(uint16_t iMinorVersion)
	{
		m_iMinorVersion = iMinorVersion;
	}

	// Sets DLL name
	void PEExportInfo::setName(const std::string& sName)
	{
		m_sName = sName;
	}

	// Sets ordinal base
	void PEExportInfo::setOrdinalBase(uint32_t iOrdinalBase)
	{
		m_iOrdinalBase = iOrdinalBase;
	}

	// Sets number of functions
	void PEExportInfo::setNumberOfFunctions(uint32_t iNumberOfFunctions)
	{
		m_iNumberOfFunctions = iNumberOfFunctions;
	}

	// Sets number of function names
	void PEExportInfo::setNumberOfNames(uint32_t iNumberOfNames)
	{
		m_iNumberOfNames = iNumberOfNames;
	}

	// Sets RVA of function address table
	void PEExportInfo::setRVAOfFunctions(uint32_t iRVAOfFunctions)
	{
		m_iAddressOfFunctions = iRVAOfFunctions;
	}

	// Sets RVA of function name address table
	void PEExportInfo::setRVAOfNames(uint32_t iRVAOfNames)
	{
		m_iAddressOfNames = iRVAOfNames;
	}

	// Sets RVA of name ordinals table
	void PEExportInfo::setRVAOfNameOrdinals(uint32_t iRVAOfNameOrdinals)
	{
		m_iAddressOfNameOrdinals = iRVAOfNameOrdinals;
	}

	// forward declaration
	const PEEXPORTED_FUNCTION_LIST				getExportedFunctionsList(const PEBase& peBase, PEExportInfo* peExportInfo);
	
	// Returns array of exported functions
	const PEEXPORTED_FUNCTION_LIST				getExportedFunctionsList(const PEBase& peBase)
	{
		return getExportedFunctionsList(peBase, 0);
	}

	// Returns array of exported functions and information about export
	const PEEXPORTED_FUNCTION_LIST				getExportedFunctionsList(const PEBase& peBase, PEExportInfo& peExportInfo)
	{
		return getExportedFunctionsList(peBase, &peExportInfo);
	}

	// Helper: sorts exported function list by ordinals
	struct OrdinalSorter
	{
		public:
			bool operator()(const PEExportedFunction& func1, const PEExportedFunction& func2);
	};

	// Returns array of exported functions and information about export
	const PEEXPORTED_FUNCTION_LIST				getExportedFunctionsList(const PEBase& peBase, PEExportInfo* peExportInfo)
	{
		// Returned exported functions info array
		std::vector<PEExportedFunction>		returnList;

		if (peBase.hasExports())
		{
			// Check the length in bytes of the section containing export directory
			if (peBase.getSectionDataLengthFromRVA(	peBase.getDirectoryRVA(IMAGE_DIRECTORY_ENTRY_EXPORT),
													peBase.getDirectoryRVA(IMAGE_DIRECTORY_ENTRY_EXPORT),
													SECTION_DATA_VIRTUAL,
													true) < sizeof(IMAGE_EXPORT_DIRECTORY))
			{
				throw PEException("Incorrect export directory", PEException::PEEXCEPTION_INCORRECT_EXPORT_DIRECTORY);
			}

			IMAGE_EXPORT_DIRECTORY exports = peBase.getSectionDataFromRVA<IMAGE_EXPORT_DIRECTORY>(	peBase.getDirectoryRVA(IMAGE_DIRECTORY_ENTRY_EXPORT),
																									SECTION_DATA_VIRTUAL,
																									true);

			unsigned long iMaxNameLength;
			if (peExportInfo)
			{
				// Save some export info data
				peExportInfo->setCharacteristics(exports.iCharacteristics);
				peExportInfo->setMajorVersion(exports.iMajorVersion);
				peExportInfo->setMinorVersion(exports.iMinorVersion);

				// Get byte count that we have for dll name
				if ((iMaxNameLength = peBase.getSectionDataLengthFromRVA(	exports.iName, 
																			exports.iName, 
																			SECTION_DATA_VIRTUAL, 
																			true)) < 2)
				{
					throw PEException("Incorrect export directory", PEException::PEEXCEPTION_INCORRECT_EXPORT_DIRECTORY);
				}

				// Get dll name pointer
				const char* sDllName = peBase.getSectionDataFromRVA(exports.iName, SECTION_DATA_VIRTUAL, true);

				// Check for null-termination
				if (NOT PEUtils::isNullTerminated(sDllName, iMaxNameLength))
					throw PEException("Incorrect export directory", PEException::PEEXCEPTION_INCORRECT_EXPORT_DIRECTORY);

				//Save the rest of export information data
				peExportInfo->setName(sDllName);
				peExportInfo->setNumberOfFunctions(exports.iNumberOfFunctions);
				peExportInfo->setNumberOfNames(exports.iNumberOfNames);
				peExportInfo->setOrdinalBase(exports.iBase);
				peExportInfo->setRVAOfFunctions(exports.iAddressOfFunctions);
				peExportInfo->setRVAOfNames(exports.iAddressOfNames);
				peExportInfo->setRVAOfNameOrdinals(exports.iAddressOfNameOrdinals);
				peExportInfo->setTimeStamp(exports.iTimeDateStamp);
			}

			if (!exports.iNumberOfFunctions)
				return returnList;

			// Check IMAGE_EXPORT_DIRECTORY fields
			if (exports.iNumberOfNames > exports.iNumberOfFunctions)
			{
				throw PEException("Incorrect export directory", PEException::PEEXCEPTION_INCORRECT_EXPORT_DIRECTORY);
			}

			// Check some export directory fields
			if (	(NOT exports.iAddressOfNameOrdinals && exports.iAddressOfNames) 
					||
					(exports.iAddressOfNameOrdinals && !exports.iAddressOfNames) 
					||
					NOT exports.iAddressOfFunctions
					|| 
					exports.iNumberOfFunctions >= PEUtils::MAX_DWORD / sizeof(uint32_t)
					|| 
					exports.iNumberOfNames > PEUtils::MAX_DWORD / sizeof(uint32_t)
					|| 
					NOT PEUtils::isSumSafe(exports.iAddressOfFunctions, exports.iNumberOfFunctions * sizeof(uint32_t))
					|| 
					NOT PEUtils::isSumSafe(exports.iAddressOfNames, exports.iNumberOfNames * sizeof(uint32_t))
					|| 
					NOT PEUtils::isSumSafe(exports.iAddressOfNameOrdinals, exports.iNumberOfFunctions * sizeof(uint32_t))
					|| 
					NOT PEUtils::isSumSafe(	peBase.getDirectoryRVA(IMAGE_DIRECTORY_ENTRY_EXPORT), 
											peBase.getDirectorySize(IMAGE_DIRECTORY_ENTRY_EXPORT))
			) {
				throw PEException("Incorrect export directory", PEException::PEEXCEPTION_INCORRECT_EXPORT_DIRECTORY);
			}

			// Check if it is enough bytes to hold AddressOfFunctions table
			if (	peBase.getSectionDataLengthFromRVA(	exports.iAddressOfFunctions, 
														exports.iAddressOfFunctions, 
														SECTION_DATA_VIRTUAL, 
														true)
					< 
					exports.iNumberOfFunctions * sizeof(uint32_t)
			) {
				throw PEException("Incorrect export directory", PEException::PEEXCEPTION_INCORRECT_EXPORT_DIRECTORY);
			}

			if (exports.iAddressOfNames)
			{
				// Check if it is enough bytes to hold name and ordinal tables
				if (	peBase.getSectionDataLengthFromRVA(	exports.iAddressOfNameOrdinals, 
															exports.iAddressOfNameOrdinals, 
															SECTION_DATA_VIRTUAL, 
															true)
						< 
						exports.iNumberOfNames * sizeof(uint32_t)
				) {
					throw PEException("Incorrect export directory", PEException::PEEXCEPTION_INCORRECT_EXPORT_DIRECTORY);
				}

				if (	peBase.getSectionDataLengthFromRVA(	exports.iAddressOfNames, 
															exports.iAddressOfNames, 
															SECTION_DATA_VIRTUAL, 
															true)
						< 
						exports.iNumberOfNames * sizeof(uint32_t)
				) {
					throw PEException("Incorrect export directory", PEException::PEEXCEPTION_INCORRECT_EXPORT_DIRECTORY);
				}
			}

			for (uint32_t iOrdinal = 0; iOrdinal < exports.iNumberOfFunctions; iOrdinal++)
			{
				// Get function address
				// Sum and multiplication are safe (checked above)
				uint32_t iRVA = peBase.getSectionDataFromRVA<uint32_t>(	exports.iAddressOfFunctions + iOrdinal * sizeof(uint32_t),
																		SECTION_DATA_VIRTUAL,
																		true);

				// If we have a skip
				if (NOT iRVA)
					continue;

				PEExportedFunction func;
				func.setRVA(iRVA);

				if (NOT PEUtils::isSumSafe(exports.iBase, iOrdinal)
					||
					exports.iBase + iOrdinal > PEUtils::MAX_WORD
				) {
					throw PEException("Incorrect export directory", PEException::PEEXCEPTION_INCORRECT_EXPORT_DIRECTORY);
				}

				func.setOrdinal(static_cast<uint16_t>(iOrdinal + exports.iBase));

				// Scan for function name ordinal
				for (uint32_t i = 0; i < exports.iNumberOfNames; i++)
				{
					uint16_t iOrdinal2 = peBase.getSectionDataFromRVA<uint16_t>(	exports.iAddressOfNameOrdinals + i * sizeof(uint16_t), 
																					SECTION_DATA_VIRTUAL, 
																					true);

					// If function has name (and name ordinal)
					if (iOrdinal == iOrdinal2)
					{
						// Get function name
						// Sum and multiplication are safe (checked above)
						uint32_t iFunctionNameRVA = peBase.getSectionDataFromRVA<uint32_t>(	exports.iAddressOfNames + i * sizeof(uint32_t), 
																							SECTION_DATA_VIRTUAL, 
																							true);

						// Get byte count that we have for function name
						if ((iMaxNameLength = peBase.getSectionDataLengthFromRVA(	iFunctionNameRVA, 
																					iFunctionNameRVA, 
																					SECTION_DATA_VIRTUAL, 
																					true)
																				) < 2
						) {
							throw PEException("Incorrect export directory", PEException::PEEXCEPTION_INCORRECT_EXPORT_DIRECTORY);
						}

						// Get function name pointer
						const char* pFuncName = peBase.getSectionDataFromRVA(iFunctionNameRVA, SECTION_DATA_VIRTUAL, true);

						//Check for null-termination
						if (NOT PEUtils::isNullTerminated(pFuncName, iMaxNameLength))
							throw PEException("Incorrect export directory", PEException::PEEXCEPTION_INCORRECT_EXPORT_DIRECTORY);

						//Save function info
						func.setName(pFuncName);
						func.setNameOrdinal(iOrdinal2);

						// If the function is just a redirect, save its name
						if (	iRVA >=	peBase.getDirectoryRVA(IMAGE_DIRECTORY_ENTRY_EXPORT) 
										+ 
										sizeof(IMAGE_DIRECTORY_ENTRY_EXPORT) 
								&&
								iRVA <	peBase.getDirectoryRVA(IMAGE_DIRECTORY_ENTRY_EXPORT) 
										+ 
										peBase.getDirectorySize(IMAGE_DIRECTORY_ENTRY_EXPORT))
						{
							if ((iMaxNameLength = peBase.getSectionDataLengthFromRVA(iRVA, iRVA, SECTION_DATA_VIRTUAL, true)) < 2)
								throw PEException("Incorrect export directory", PEException::PEEXCEPTION_INCORRECT_EXPORT_DIRECTORY);

							// Get forwarded function name pointer
							const char* pForwardedFuncName = peBase.getSectionDataFromRVA(iRVA, SECTION_DATA_VIRTUAL, true);

							// Check for null-termination
							if (NOT PEUtils::isNullTerminated(pForwardedFuncName, iMaxNameLength))
								throw PEException("Incorrect export directory", PEException::PEEXCEPTION_INCORRECT_EXPORT_DIRECTORY);

							// Set the name of forwarded function
							func.setForwardedName(pForwardedFuncName);
						} {
							break;
						}
					}
				}

				//Add function info to output array
				returnList.push_back(func);
			}
		}

		return returnList;
	}


// Helper export functions
// Returns pair: <ordinal base for supplied functions; maximum ordinal value for supplied functions>
const std::pair<uint16_t, uint16_t>			getExportedOrdinalLimits(const PEEXPORTED_FUNCTION_LIST& peExports);

// Checks if exported function name already exists
bool										doesExportedNameExists(const std::string& sFunctionName, const PEEXPORTED_FUNCTION_LIST& peExports);

// Checks if exported function ordinal already exists
bool										doesExportedOrdinalExists(uint16_t iOrdinal, const PEEXPORTED_FUNCTION_LIST& peExports);

}