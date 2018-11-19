#include <iostream>
#include <fstream>
#include <OpenPE.h>
#include "../Samples/lib.h"

using namespace OpenPE;

int main(int argc, char* argv[])
{
	if (argc NOT_EQUAL_TO 2)
	{
		std::cout << "Usage: AddressConventions.exe PE_FILE" << std::endl;
		return 0;
	}

	std::ifstream peFile(argv[1], std::ios::in | std::ios::binary);
	if (NOT peFile)
	{
		std::cout << "Unable to open file:" << argv[1] << std::endl;
		return -1;
	}

	std::cout << "Opening PE File >> " << argv[1] << std::endl;

	try
	{
		// Create an instance of PE or PE + class using the factory
		PEBase peImage(PEFactory::createPE(peFile, false));

		std::cout << "***** OpenPE *****" << std::hex << std::showbase << std::endl;
		std::cout << "Reading PE Sections" << std::hex << std::showbase << std::endl;
		const SECTION_LIST peSections = peImage.getImageSectionList();

		for (SECTION_LIST::const_iterator itr = peSections.begin(); itr != peSections.end(); ++itr)
		{
			const PESection& section = *itr;

			std::cout	<< "Section [ "				<< section.GetName() << "]" << std::endl
						<< " -> RVA: "				<< section.getVirtualAddress() << std::endl
						<< " -> VA:"				<< peImage.getRVAToVA_64(section.getVirtualAddress()) << std::endl
						<< " -> File Offset: "		<< peImage.getRVAToFileOffset(section.getVirtualAddress()) << std::endl
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