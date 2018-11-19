#pragma once
#include <stdint.h>

namespace OpenPE
{
	// PE Types
	enum PEType
	{
		PEType_32,
		PEType_64
	};

	#define NOT												!
	#define NOT_EQUAL_TO									!=

	const uint16_t MZ_SIGNATURE								= 0x5A4D;							// "MZ"
	const uint32_t PE_SIGNATURE								= 0x4550;							// "PE"
	const uint32_t IMAGE_NUMBER_OF_DATA_DIRECTORY_ENTRIES	= 16;
	const uint32_t IMAGE_NT_OPTIONAL_HDR32_MAGIC			= 0x10b;
	const uint32_t IMAGE_NT_OPTIONAL_HDR64_MAGIC			= 0x20b;

	//Imports
	const uint32_t IMAGE_ORDINAL_FLAG32						= 0x80000000;
	const uint64_t IMAGE_ORDINAL_FLAG64						= 0x8000000000000000ull;

	// Section Flags
	const uint32_t IMAGE_SCN_LNK_NRELOC_OVFL				= 0x01000000;	// The section contains extended relocations. 
																			// The count of relocations for the section exceeds the 16 bits 
																			// that is reserved for it in the section header. 
																			// If the NumberOfRelocations field in the section header is 0xffff, 
																			// the actual relocation count is stored in the VirtualAddress field of the first relocation. 
																			// It is an error if IMAGE_SCN_LNK_NRELOC_OVFL is set and there are fewer 
																			// than 0xffff relocations in the section.
	const uint32_t IMAGE_SCN_MEM_DISCARDABLE				= 0x02000000;	// The section can be discarded as needed.
	const uint32_t IMAGE_SCN_MEM_NOT_CACHED					= 0x04000000;	// The section cannot be cached.
	const uint32_t IMAGE_SCN_MEM_NOT_PAGED					= 0x08000000;	// The section cannot be paged.
	const uint32_t IMAGE_SCN_MEM_SHARED						= 0x10000000;	// The section can be shared in memory.
	const uint32_t IMAGE_SCN_MEM_EXECUTE					= 0x20000000;	// The section can be executed as code.
	const uint32_t IMAGE_SCN_MEM_READ						= 0x40000000;	// The section can be read.
	const uint32_t IMAGE_SCN_MEM_WRITE						= 0x80000000;	// The section can be written to.
	const uint32_t IMAGE_SCN_CNT_CODE						= 0x00000020;	// The section contains executable code.
	const uint32_t IMAGE_SCN_CNT_INITIALIZED_DATA			= 0x00000040;	// The section contains initialized data.
	const uint32_t IMAGE_SCN_CNT_UNINITIALIZED_DATA			= 0x00000080;	// The section contains uninitialized data.

	// Image Dll Characteristics

	// Image File Characteristics
	const uint32_t IMAGE_FILE_RELOCS_STRIPPED				= 0x0001;		// Relocations info stripped from File.

	// Directory Entries
	const uint32_t IMAGE_DIRECTORY_ENTRY_EXPORT				= 0;
	const uint32_t IMAGE_DIRECTORY_ENTRY_IMPORT				= 1;
	const uint32_t IMAGE_DIRECTORY_ENTRY_RESOURCE			= 2;
	const uint32_t IMAGE_DIRECTORY_ENTRY_EXCEPTION			= 3;
	const uint32_t IMAGE_DIRECTORY_ENTRY_SECURITY			= 4;
	const uint32_t IMAGE_DIRECTORY_ENTRY_BASERELOC			= 5;
	const uint32_t IMAGE_DIRECTORY_ENTRY_DEBUG				= 6;
	const uint32_t IMAGE_DIRECTORY_ENTRY_ARCHITECTURE		= 7;
	const uint32_t IMAGE_DIRECTORY_ENTRY_GLOBALPTR			= 8;
	const uint32_t IMAGE_DIRECTORY_ENTRY_TLS				= 9;
	const uint32_t IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG		= 10;
	const uint32_t IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT		= 11;
	const uint32_t IMAGE_DIRECTORY_ENTRY_IAT				= 12;
	const uint32_t IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT		= 13;
	const uint32_t IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR		= 14;

	//Subsystem Values
	const uint32_t IMAGE_SUBSYSTEM_UNKNOWN					= 0;	// Unknown subsystem.
	const uint32_t IMAGE_SUBSYSTEM_NATIVE					= 1;	// Image doesn't require a subsystem.
	const uint32_t IMAGE_SUBSYSTEM_WINDOWS_GUI				= 2;	// Image runs in the Windows GUI subsystem.
	const uint32_t IMAGE_SUBSYSTEM_WINDOWS_CUI				= 3;	// Image runs in the Windows character subsystem.
	const uint32_t IMAGE_SUBSYSTEM_OS2_CUI					= 5;	// Image runs in the OS/2 character subsystem.
	const uint32_t IMAGE_SUBSYSTEM_POSIX_CUI				= 7;	// Image runs in the Posix character subsystem.
	const uint32_t IMAGE_SUBSYSTEM_NATIVE_WINDOWS			= 8;	// Image is a native Win9x driver.
	const uint32_t IMAGE_SUBSYSTEM_WINDOWS_CE_GUI			= 9;	// Image runs in the Windows CE subsystem.
	const uint32_t IMAGE_SUBSYSTEM_EFI_APPLICATION			= 10;	//
	const uint32_t IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER	= 11;	//
	const uint32_t IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER		= 12;	//
	const uint32_t IMAGE_SUBSYSTEM_EFI_ROM					= 13;
	const uint32_t IMAGE_SUBSYSTEM_XBOX						= 14;
	const uint32_t IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16;


	struct Image_Dos_Header
	{
		uint16_t e_cblp;                      // Bytes on last page of file
		uint16_t e_cp;                        // Pages in file
		uint16_t e_crlc;                      // Relocations
		uint16_t e_cparhdr;                   // Size of header in paragraphs
		uint16_t e_minalloc;                  // Minimum extra paragraphs needed
		uint16_t e_maxalloc;                  // Maximum extra paragraphs needed
		uint16_t e_ss;                        // Initial (relative) SS value
		uint16_t e_sp;                        // Initial SP value
		uint16_t e_csum;                      // Checksum
		uint16_t e_ip;                        // Initial IP value
		uint16_t e_cs;                        // Initial (relative) CS value
		uint16_t e_lfarlc;                    // File address of relocation table
		uint16_t e_ovno;                      // Overlay number
		uint16_t e_res[4];                    // Reserved words
		uint16_t e_oemid;                     // OEM identifier (for e_oeminfo)
		uint16_t e_oeminfo;                   // OEM information; e_oemid specific
		uint16_t e_res2[10];                  // Reserved words
	};

	struct Image_Dos
	{
		uint16_t			Signature;			// Magic Number
		Image_Dos_Header	DosHeader;
		int32_t				PointerToPEHeader;	// File address of new exe header
		//					DosStub
	};

	struct Image_Data_Directory
	{
		uint32_t		RVA;
		uint32_t		Size;
	};

	struct Image_COFF_FileHeader
	{
		// COFF Header
		uint32_t		Signature;
		uint16_t		Machine;
		uint16_t		NumberOfSections;
		uint32_t		TimeDateStamp;
		uint32_t		PointerToSymbolTable;
		uint32_t		NumberOfSymbolTables;
		uint16_t		SizeOfOptionalHeader;
		uint16_t		Characteristics;
	};

	///////////////////////////////////////////// 32 /////////////////////////////////////////
	struct Image_COFF_OptionalHeader32
	{
		// Standard COFF Fields
		uint16_t		Magic;
		uint8_t			MajorLinkerVersion;
		uint8_t			MinorLinkerVersion;
		uint32_t		SizeOfCode;					// Sum of all sections
		uint32_t		SizeOfInitializedData;
		uint32_t		SizeOfUninitializedData;
		uint32_t		AddressOfEntryPoint;		// Relative Virtual Address (RVA)
		uint32_t		BaseOfCode;					// Relative Virtual Address (RVA)
		uint32_t		BaseOfData;					// Relative Virtual Address (RVA)

		// NT specific fields
		uint32_t		ImageBase;
		uint32_t		SectionAlignment;
		uint32_t		FileAlignment;
		uint16_t		MajorOperatingSystemVersion;
		uint16_t		MinorOperatingSystemVersion;
		uint16_t		MajorImageVersion;
		uint16_t		MinorImageVersion;
		uint16_t		MajorSubsystemVersion;
		uint16_t		MinorSubsystemVersion;
		uint32_t		Win32Versionvalue;			// zeros filled
		uint32_t		SizeOfImage;
		uint32_t		SizeOfHeaders;
		uint32_t		Checksum;					// images doesn't check
		uint16_t		Subsystem;
		uint16_t		DllCharacteristics;
		uint32_t		SizeOfStackReserve;
		uint32_t		SizeOfStackCommit;
		uint32_t		SizeOfHeapReserve;
		uint32_t		SizeOfHeapCommit;
		uint32_t		LoaderFlags;				// zeros filled
		uint32_t		NumberOfRVAAndSizes;

		Image_Data_Directory	DataDirectory[IMAGE_NUMBER_OF_DATA_DIRECTORY_ENTRIES];
	};

	struct Image_NT_Headers32
	{
		Image_COFF_FileHeader			FileHeader;
		Image_COFF_OptionalHeader32		OptionalHeader;
	};

	struct Image_TLS_Directory32
	{
		uint32_t			StartAddressOfRawData;
		uint32_t			EndAddressOfRawData;
		uint32_t			AddressOfIndex;			// PDWORD
		uint32_t			AddressOfCallback;		// PIMAGE_TLS_CALLBACK*
		uint32_t			SizeOfZeroFill;
		uint32_t			Charecteristics;
	};

	// Load Configuration Directory Entry
	struct Image_Load_Config_Directory32
	{
		uint32_t			Size;
		uint32_t			TimeDateStamp;
		uint16_t			MajorVersion;
		uint16_t			MinorVersion;
		uint32_t			GlobalFlagsClear;
		uint32_t			GlobalFlagsSet;
		uint32_t			CriticalSectionDefaultTimeout;
		uint32_t			DeCommitFreeBlockThreshold;
		uint32_t			DeCommitTotalFreeThreshold;
		uint32_t			LockPrefixTable;
		uint32_t			MaximumAllocationSize;
		uint32_t			VirtualMemoryThreshold;
		uint32_t			ProcessHeapFlags;
		uint32_t			ProcessAffinityMask;
		uint16_t			CSDVersion;
		uint16_t			Reserved;
		uint32_t			EditList;
		uint32_t			SecurityCookie;
		uint32_t			SEHandlerTable;
		uint32_t			SEHandlerCount;
	};
	//////////////////////////////////////////////////////////////////////////////////////////

	///////////////////////////////////////////// 64 /////////////////////////////////////////
	struct Image_COFF_OptionalHeader64
	{
		// Standard COFF Fields
		uint16_t		Magic;
		uint8_t			MajorLinkerVersion;
		uint8_t			MinorLinkerVersion;
		uint32_t		SizeOfCode;					// Sum of all sections
		uint32_t		SizeOfInitializedData;
		uint32_t		SizeOfUninitializedData;
		uint32_t		AddressOfEntryPoint;		// Relative Virtual Address (RVA)
		uint32_t		BaseOfCode;					// Relative Virtual Address (RVA)

		// NT specific fields
		uint64_t		ImageBase;					// 64 bits
		uint32_t		SectionAlignment;
		uint32_t		FileAlignment;
		uint16_t		MajorOperatingSystemVersion;
		uint16_t		MinorOperatingSystemVersion;
		uint16_t		MajorImageVersion;
		uint16_t		MinorImageVersion;
		uint16_t		MajorSubsystemVersion;
		uint16_t		MinorSubsystemVersion;
		uint32_t		Win32Versionvalue;			// zeros filled
		uint32_t		SizeOfImage;
		uint32_t		SizeOfHeaders;
		uint32_t		Checksum;					// images doesn't check
		uint16_t		Subsystem;
		uint16_t		DllCharacteristics;
		uint64_t		SizeOfStackReserve;			// 64 bits
		uint64_t		SizeOfStackCommit;			// 64 bits
		uint64_t		SizeOfHeapReserve;			// 64 bits
		uint64_t		SizeOfHeapCommit;			// 64 bits
		uint32_t		LoaderFlags;				// zeros filled
		uint32_t		NumberOfRVAAndSizes;

		Image_Data_Directory	DataDirectory[IMAGE_NUMBER_OF_DATA_DIRECTORY_ENTRIES];
	};

	struct Image_NT_Headers64
	{
		Image_COFF_FileHeader			FileHeader;
		Image_COFF_OptionalHeader64		OptionalHeader;
	};

	struct Image_TLS_Directory64
	{
		uint64_t			StartAddressOfRawData;
		uint64_t			EndAddressOfRawData;
		uint64_t			AddressOfIndex;			// PDWORD
		uint64_t			AddressOfCallback;		// PIMAGE_TLS_CALLBACK*
		uint64_t			SizeOfZeroFill;
		uint64_t			Charecteristics;
	};

	// Load Configuration Directory Entry
	struct Image_Load_Config_Directory64
	{
		uint64_t			Size;
		uint64_t			TimeDateStamp;
		uint32_t			MajorVersion;
		uint32_t			MinorVersion;
		uint64_t			GlobalFlagsClear;
		uint64_t			GlobalFlagsSet;
		uint64_t			CriticalSectionDefaultTimeout;
		uint64_t			DeCommitFreeBlockThreshold;
		uint64_t			DeCommitTotalFreeThreshold;
		uint64_t			LockPrefixTable;
		uint64_t			MaximumAllocationSize;
		uint64_t			VirtualMemoryThreshold;
		uint64_t			ProcessHeapFlags;
		uint64_t			ProcessAffinityMask;
		uint32_t			CSDVersion;
		uint32_t			Reserved;
		uint64_t			EditList;
		uint64_t			SecurityCookie;
		uint64_t			SEHandlerTable;
		uint64_t			SEHandlerCount;
	};
	//////////////////////////////////////////////////////////////////////////////////////////

	// Section Header Format
	struct Image_Section_Header
	{
		uint8_t				Name[8];
		union
		{
			uint32_t		PhysicalAddress;			
			uint32_t		VirtualSize;
		} Misc;

		uint32_t			VirtualAddress;
		uint32_t			SizeOfRawData;
		uint32_t			PointerToRawData;
		uint32_t			PointerToRelocations;
		uint32_t			PointerToLineNumbers;
		uint16_t			NumberOfRelocations;
		uint16_t			NumberOfLineNumbers;
		uint32_t			Characteristics;
	};

//#define SAVE_ISTREAM_STATE(__iFileStream__) \
//	std::ios_base::iostate iState = __iFileStream__.exceptions(); \
//	std::streamoff oldStreamOffset = __iFileStream__.tellg(); \
//
//#define RESTORE_ISTREAM_STATE(__iFileStream__) \
//	__iFileStream__.exceptions(iState); \
//	__iFileStream__.seekg(oldStreamOffset); \
//	__iFileStream__.clear(); \

}