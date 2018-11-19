#pragma once

#include <vector>
#include <string>
#include "OpenPEStructures.h"
#include "OpenPEDirectory.h"
#include "OpenPEBase.h"

namespace OpenPE
{
	// Class representing Imported function
	class PEImportedFunction
	{
		public:
			// Default Constructor
			PEImportedFunction();

			// Returns 'true' if imported function has 'Name' (& Hint)
			bool					hasName() const;

			// Returns 'Name' of the function
			const std::string&		getName() const;

			// Returns 'Hint'
			uint16_t				getHint() const;

			// Returns 'Ordinal' of the function
			uint16_t				getOrdinal() const;

			// Returns IAT entry VA (usable if image has both IAT and original IAT and is bound)
			uint64_t				getIAT_VA() const;
		public:
			// Setters do not change everything inside image, they are used by PE class
			// You also can use them to rebuild image imports

			// Sets 'Name' of function
			void					setName(const std::string& sName);

			// Sets 'Hint'
			void					setHint(uint16_t iHint);

			// Sets 'Ordinal'
			void					setOrdinal(uint16_t iOrdinal);

			// Sets IAT entry VA (usable if image has both IAT and original IAT and is bound)
			void					setIAT_VA(uint64_t iVA);
		private:
			std::string				m_sName;
			uint16_t				m_iHint;
			uint16_t				m_iOrdinal;
			uint64_t				m_iIAT_VA;
	};

	// Class representing Imported Library function
	class PEImportLibrary
	{
		public:
			typedef std::vector<PEImportedFunction>		IMPORTED_LIST;
		public:
			// Default Constructor
			PEImportLibrary();

			// Returns 'Name' of the Library
			const std::string&				getName() const;

			// Returns RVA to Import Address Table(IAT)
			uint32_t						getRVAToIAT() const;

			// Returns RVA to Original Import Address Table(Original IAT) 
			uint32_t						getRVATOOriginalIAT() const;

			// Returns TimeStamp
			uint32_t						getTimeStamp() const;

			// Returns 'Imported' function list
			const IMPORTED_LIST&			getImportedFunctionList() const;
		public:
			// Setters do not change everything inside image, they are used by PE class
			// You also can use them to rebuild image imports

			// Sets 'Name' of the Library
			void							setName(const std::string& sName);

			// Sets RVA to Import Address Table(IAT)
			void							setRVAToIAT(uint32_t iRVAToIAT);

			// Sets RVA to Original Import Address Table(Original IAT) 
			void							setRVATOOriginalIAT(uint32_t iRVAToOriginalIAT);

			// Sets TimeStamp
			void							setTimeStamp(uint32_t iTimeStamp);

			// Adds 'Imported' function to list
			void							addImport(const PEImportedFunction& func);

			// Clears 'Imported' function list
			void							clearImports();
		private:
			std::string						m_sName;
			uint32_t						m_iRVAToIAT;
			uint32_t						m_iRVAToOriginalIAT;
			uint32_t						m_iTimeStamp;

			IMPORTED_LIST					m_vImportedFunctionList;
	};

	// Simple Import Directory Rebuilder
	// Class representing Import Rebuilder advanced settings
	class PEImportRebuilderSettings
	{
		public:
			// If set_to_pe_headers = true, IMAGE_DIRECTORY_ENTRY_IMPORT entry will be reset
			// to new value after import rebuilding
			// If auto_zero_directory_entry_iat = true, IMAGE_DIRECTORY_ENTRY_IAT will be set to zero
			// IMAGE_DIRECTORY_ENTRY_IAT is used by loader to temporarily make section, where IMAGE_DIRECTORY_ENTRY_IAT RVA points, writeable
			// to be able to modify IAT thunks
			explicit		PEImportRebuilderSettings(bool bSetToPEHeaders = true, bool bAutoZeroDirectoryList = false);

			// Returns offset from section start where import directory data will be placed
			uint32_t		getOffsetFromSectionStart() const;

			// Returns true if Original import address table (IAT) will be rebuilt
			bool			canBuildOriginalIAT() const;

			// Returns true if Original import address and import address tables will not be rebuilt,
			// works only if import descriptor IAT (and orig.IAT, if present) RVAs are not zero
			bool			saveIATAndOriginalIATRVAs() const;

			// Returns true if Original import address and import address tables contents will be rewritten
			// works only if import descriptor IAT (and orig.IAT, if present) RVAs are not zero
			// and save_iat_and_original_iat_rvas is true
			bool			rewriteIATAndOriginalIATContents() const;

			// Returns true if original missing IATs will be rebuilt
			// (only if IATs are saved)
			bool			fillMissingOriginalIATs() const;
			
			// Returns true if PE headers should be updated automatically after rebuilding of imports
			bool			autoSetToPEHeaders() const;
			
			// Returns true if IMAGE_DIRECTORY_ENTRY_IAT must be zeroed, works only if auto_set_to_pe_headers = true
			bool			zeroDirectoryEntryIAT() const;

			// Returns true if the last section should be stripped automatically, if imports are inside it
			bool			autoStripLastSectionEnabled() const;

		public: //Setters
			// Sets offset from section start where import directory data will be placed
			void			setOffsetFromSectionStart(uint32_t iOffset);

			// Sets if Original import address table (IAT) will be rebuilt
			void			buildOriginalIAT(bool bEnable);

			// Sets if Original import address and import address tables will not be rebuilt,
			// works only if import descriptor IAT (and orig.IAT, if present) RVAs are not zero
			// enable_rewrite_iat_and_original_iat_contents sets if Original import address and import address tables contents will be rewritten
			// works only if import descriptor IAT (and orig.IAT, if present) RVAs are not zero
			// and save_iat_and_original_iat_rvas is true
			void			saveIATAndOriginalIATRVAs(bool bEnable, bool bEnableRewriteIATAndOriginalIATContents = false);

			// Sets if original missing IATs will be rebuilt
			// (only if IATs are saved)
			void			fillMissingOriginalIATs(bool bEnable);

			// Sets if PE headers should be updated automatically after rebuilding of imports
			void			autoSetToPEHeaders(bool bEnable);

			// Sets if IMAGE_DIRECTORY_ENTRY_IAT must be zeroed, works only if auto_set_to_pe_headers = true
			void			zeroDirectoryEntryIAT(bool bEnable);

			// Sets if the last section should be stripped automatically, if imports are inside it, default true
			void			enableAutoStripLastSection(bool bEnable);

		private:
			uint32_t		m_iOffsetFromSectionStart;
			bool			m_bBuildOriginalIAT;
			bool			m_bSaveIATAndOriginalIATRVAs;
			bool			m_bFillMissingOriginalIATs;
			bool			m_bSetToPEHeaders;
			bool			m_bZeroDirectoryEntryIAT;
			bool			m_bRewriteIATAndOoriginalIATContents;
			bool			m_bAutoStripLastSection;
	};

	typedef	std::vector<PEImportLibrary>		PEIMPORTED_FUNCTIONS_LIST;

	// Returns imported functions list with related libraries info
	const PEIMPORTED_FUNCTIONS_LIST				getImportedFunctionsList(const PEBase& peBase);

	template<typename PEClassType>
	const PEIMPORTED_FUNCTIONS_LIST				getImportedFunctionsBase(const PEBase& peBase);

	// TODO - PEImportAdder
	// You can get all image imports with get_imported_functions() function
	// You can use returned value to, for example, add new imported library with some functions
	// to the end of list of imported libraries
	// To keep PE file working, rebuild its imports with save_iat_and_original_iat_rvas = true (default)
	// Don't add new imported functions to existing imported library entries, because this can cause
	// rewriting of some used memory (or other IAT/orig.IAT fields) by system loader
	// The safest way is just adding import libraries with functions to the end of imported_functions_list array
	//const PEImageDirectory						rebuildImports(	PEBase& peBase, 
	//															const PEIMPORTED_FUNCTIONS_LIST& imports, 
	//															PESection& importSection, 
	//															const PEImportRebuilderSettings& import_settings = PEImportRebuilderSettings());

	// TODO - PEImportAdder
	//template<typename PEClassType>
	//const PEImageDirectory						rebuildImportsBase(	PEBase& pe, 
	//																const PEIMPORTED_FUNCTIONS_LIST& imports,
	//																PESection& importSection,
	//																const PEImportRebuilderSettings& import_settings = PEImportRebuilderSettings());
}