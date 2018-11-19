#include <iostream>
#include <fstream>
#include "OpenPE.h"
#include "../Samples/lib.h"

using namespace OpenPE;

int main(int argc, char* argv[])
{
	if (argc NOT_EQUAL_TO 2)
	{
		std::cout << "Usage: SectionsAndAddresses.exe PE_FILE" << std::endl;
		return 0;
	}

	std::ifstream peFile(argv[1], std::ios::in | std::ios::binary);
	if (NOT peFile)
	{
		std::cout << "Unable to open file: " << argv[1] << std::endl;
		return -1;
	}

	std::cout << "Opening PE File >> " << argv[1] << std::endl;

	try
	{
		// Create an instance of PE or PE + class using the factory
		PEBase peImage(PEFactory::createPE(peFile, false));

		std::cout << "***** OpenPE *****" << std::hex << std::showbase << std::endl;

		// Output the name of the section in which the entry point of the PE file is located
		// In tricky PE files, the entry point can be in the header, then section_from_rva throws an exception
		std::cout << "EP Section Name: " << peImage.getSectionFromRVA(peImage.getEntryPoint()).GetName() << std::endl;

		// The length of raw section data
		std::cout << "EP Section Data length:" << std::dec << peImage.getSectionDataLengthFromRVA(peImage.getEntryPoint()) << std::endl;

		// If the PE file has imports, we will display the name of the section in which they are located
		if (peImage.hasImports())
		{
			std::cout << "Import Section Name: " << peImage.getSectionFromDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT).GetName() << std::endl;
		}
	}
	catch (PEException& e)
	{
		std::cout << "Exception: " << e.what() << std::endl;
		return -1;
	}

	return 0;
}