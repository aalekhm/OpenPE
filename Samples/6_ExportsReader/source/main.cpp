#include <iostream>
#include <fstream>
#include "OpenPE.h"
#include "../Samples/lib.h"

using namespace OpenPE;

int main(int argc, char* argv[])
{
	if (argc NOT_EQUAL_TO 2)
	{
		std::cout << "Usage: ExportsReader.exe PE_FILE" << std::endl;
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

		// Lets check if there are any Imports in the file
		if (NOT peImage.hasExports())
		{
			std::cout << "Image has no PE Exports." << std::endl;
			return -1;
		}

		std::cout << "Reading PE Exports..." << std::endl;

		// Get full export information and a list of exported functions
		PEExportInfo peExportInfo;
		const PEEXPORTED_FUNCTION_LIST peExports = getExportedFunctionsList(peImage, peExportInfo);

		// We will derive some information about exports :
		std::cout	<< "Export info"	<< std::endl
					<< "Library name: " << peExportInfo.getName() << std::endl
					<< "Timestamp: "	<< peExportInfo.getTimeStamp() << std::endl
					<< "Ordinal base: " << peExportInfo.getOrdinalBase() << std::endl
					<< std::endl;

		// List the sections and display information about them
		for (PEEXPORTED_FUNCTION_LIST::const_iterator it = peExports.begin(); it != peExports.end(); ++it)
		{
			// Exported Function
			const PEExportedFunction& func = *it;

			std::cout << "[+] ";
			if (func.hasName()) // If the function has a name, print it out and the ordinal of the name
				std::cout << func.getName() << ", name ordinal: " << func.getNameOrdinal() << " ";

			// Ordinal functions
			std::cout << "ORD: " << func.getOrdinal();

			// If the function is forward (forwarding to another DLL), output the name of the forward
			if (func.isForwarded())
				std::cout << std::endl << " -> " << func.getForwardedName();

			std::cout << std::endl;
		}
	}
	catch (PEException& e)
	{
		std::cout << "Exception: " << e.what() << std::endl;
		return -1;
	}

	return 0;
}