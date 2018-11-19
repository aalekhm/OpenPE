#pragma once
#include <stdint.h>
#include "OpenPEBase.h"

namespace OpenPE
{
	// Class representing Exported Function
	class PEExportedFunction
	{
		public:
			// Default Constructor
			PEExportedFunction();

			// Returns ordinal of function (actually, ordinal = hint + ordinal base)
			uint16_t			getOrdinal() const;

			// Returns RVA of function
			uint32_t			getRVA() const;

			// Returns true if function has name and name ordinal
			bool				hasName() const;

			// Returns name of function
			const std::string&	getName() const;

			// Returns name ordinal of function
			uint16_t			getNameOrdinal() const;

			// Returns true if function is forwarded to other library
			bool				isForwarded() const;

			// Returns the name of forwarded function
			const std::string&	getForwardedName() const;

		public:
			// Setters do not change everything inside image, they are used by PE class
			// You can also use them to rebuild export directory

			// Sets ordinal of function
			void				setOrdinal(uint16_t iOrdinal);

			// Sets RVA of function
			void				setRVA(uint32_t	iRVA);

			// Sets name of function (or clears it, if empty name is passed)
			void				setName(const std::string& sName);

			// Sets name ordinal
			void				setNameOrdinal(uint16_t iNameOrdinal);

			// Sets forwarded function name (or clears it, if empty name is passed)
			void				setForwardedName(const std::string& sName);

		private:
			uint16_t			m_iOrdinal;
			uint32_t			m_iRVA;
			std::string			m_sName;
			bool				m_bHasName;
			uint16_t			m_iNameOrdinal;
			bool				m_bForwarded;
			std::string			m_sForwardedName;
	};

	// Class representing export information
	class PEExportInfo
	{
		public:
			// Default constructor
			PEExportInfo();

			// Returns characteristics
			uint32_t			getCharacteristics() const;

			// Returns TimeStamp
			uint32_t			getTimeStamp() const;

			// Returns major version
			uint16_t			getMajorVersion() const;

			// Returns minor version
			uint16_t			getMinorVersion() const;

			// Returns DLL name
			const std::string&	getName() const; 

			// Returns ordinal base
			uint32_t			getOrdinalBase() const;

			// Returns number of functions
			uint32_t			getNumberOfFunctions() const;

			// Returns number of function names
			uint32_t			getNumberOfNames() const;

			// Returns RVA of function address table
			uint32_t			getRVAOfFunctions() const;

			// Returns RVA of function name address table
			uint32_t			getRVAOfNames() const;

			// Returns RVA of name ordinals table
			uint32_t			getRVAOfNameOrdinals() const;

		public:
			// Setters do not change everything inside image, they are used by PE class
			// You can also use them to rebuild export directory using rebuild_exports

			// Sets Characteristics
			void				setCharacteristics(uint32_t	iCharacteristics);

			// Sets timestamp
			void				setTimeStamp(uint32_t iTimeStamp);

			// Sets major version
			void				setMajorVersion(uint16_t iMajorVersion);

			// Sets minor version
			void				setMinorVersion(uint16_t iMinorVersion);

			// Sets DLL name
			void				setName(const std::string& sName);

			// Sets ordinal base
			void				setOrdinalBase(uint32_t iOrdinalBase);

			// Sets number of functions
			void				setNumberOfFunctions(uint32_t iNumberOfFunctions);

			// Sets number of function names
			void				setNumberOfNames(uint32_t iNumberOfNames);

			// Sets RVA of function address table
			void				setRVAOfFunctions(uint32_t iRVAOfFunctions);

			// Sets RVA of function name address table
			void				setRVAOfNames(uint32_t iRVAOfNames);

			// Sets RVA of name ordinals table
			void				setRVAOfNameOrdinals(uint32_t iRVAOfNameOrdinals);

		private:
			uint32_t			m_iCharacteristics;
			uint32_t			m_iTimeStamp;
			uint16_t			m_iMajorVersion;
			uint16_t			m_iMinorVersion;
			std::string			m_sName;
			uint32_t			m_iOrdinalBase;
			uint32_t			m_iNumberOfFunctions;
			uint32_t			m_iNumberOfNames;
			uint32_t			m_iAddressOfFunctions;
			uint32_t			m_iAddressOfNames;
			uint32_t			m_iAddressOfNameOrdinals;
	};

	// Exported Functions List typedef
	typedef std::vector<PEExportedFunction>		PEEXPORTED_FUNCTION_LIST;

	// Returns array of exported functions
	const PEEXPORTED_FUNCTION_LIST				getExportedFunctionsList(const PEBase& peBase);

	// Returns array of exported functions and information about export
	const PEEXPORTED_FUNCTION_LIST				getExportedFunctionsList(const PEBase& peBase, PEExportInfo& peExportInfo);

	// TODO - PEExportsAdder
	// Helper export functions
	// Returns pair: <ordinal base for supplied functions; maximum ordinal value for supplied functions>
	//const std::pair<uint16_t, uint16_t>			getExportedOrdinalLimits(const EXPORTED_FUNCTION_LIST& peExports);

	// Checks if exported function name already exists
	//bool										doesExportedNameExists(const std::string& sFunctionName, const EXPORTED_FUNCTION_LIST& peExports);

	// Checks if exported function ordinal already exists
	//bool										doesExportedOrdinalExists(uint16_t iOrdinal, const EXPORTED_FUNCTION_LIST& peExports);
	
	//Export directory rebuilder
	//info - export information
	//exported_functions_list - list of exported functions
	//exports_section - section where export directory will be placed (must be attached to PE image)
	//offset_from_section_start - offset from exports_section raw data start
	//save_to_pe_headers - if true, new export directory information will be saved to PE image headers
	//auto_strip_last_section - if true and exports are placed in the last section, it will be automatically stripped
	//number_of_functions and number_of_names parameters don't matter in "info" when rebuilding, they're calculated independently
	//characteristics, major_version, minor_version, timestamp and name are the only used members of "info" structure
	//Returns new export directory information
	//exported_functions_list is copied intentionally to be sorted by ordinal values later
	//Name ordinals in exported function don't matter, they will be recalculated
	//const PEImageDirectory					rebuildExports(PEBase& peBase, const PEExportInfo& peExportInfo, EXPORTED_FUNCTION_LIST peExports, PESection& peExportSection, uint32_t iOffsetFromSectionStart = 0, bool bSaveToPEHeader = true, bool bAutoStripLastSection = true);
}