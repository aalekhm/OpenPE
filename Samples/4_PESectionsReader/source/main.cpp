#include <iostream>
#include <fstream>
#include "OpenPE.h"
#include "../Samples/lib.h"

using namespace OpenPE;

int main(int argc, char* argv[])
{
	if (argc NOT_EQUAL_TO 2)
	{
		std::cout << "Usage: PESectionsReader.exe PE_FILE" << std::endl;
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
		std::cout << "reading PE Sections..." << std::endl;
		
		const SECTION_LIST peSections(peImage.getImageSectionList());

		// List the sections and display information about them
		for (SECTION_LIST::const_iterator itr = peSections.begin(); itr != peSections.end(); ++itr)
		{
			// PE Section
			const PESection peSection = *itr;

			std::cout	<< "Section ["				<< peSection.GetName() << "]"		<< std::endl		// Section Name
						<< "Characteristics: "		<< peSection.getCharacteristics()	<< std::endl		// Characteristics
						<< "Size of raw data: "		<< peSection.getSizeOfRawData()		<< std::endl		// Size of the Data in the file
						<< "Virtual address: "		<< peSection.getVirtualAddress()	<< std::endl		// Virtual Address
						<< "Virtual size: "			<< peSection.getVirtualSize()		<< std::endl		// Virtual Size
						<< std::endl;
		}
	}
	catch (PEException& e)
	{
		std::cout << "Exception: " << e.what() << std::endl;
		return -1;
	}

	return 0;
}