#include <iostream>
#include <fstream>
#include "OpenPE.h"
#include "../Samples/lib.h"

using namespace OpenPE;

int main(int argc, char* argv[])
{
	if (argc NOT_EQUAL_TO 2)
	{
		std::cout << "Usage: ImportsReader.exe PE_FILE" << std::endl;
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
		if (NOT peImage.hasImports())
		{
			std::cout << "Image has no PE Imports." << std::endl;
			return -1;
		}

		std::cout << "Reading PE Imports..." << std::endl;

		// We get the list of imported libraries with functions
		const PEIMPORTED_FUNCTIONS_LIST peImports = getImportedFunctionsList(peImage);

		// List the imported libraries and display information about them
		for (PEIMPORTED_FUNCTIONS_LIST::const_iterator it = peImports.begin(); it != peImports.end(); ++it)
		{
			// Imported Library
			const PEImportLibrary& lib = *it;

			std::cout	<< "Library["		<< lib.getName()		<< "]" << std::endl
						<< "TimeStamp: "	<< lib.getTimeStamp()	<< std::endl
						<< "RVA to IAT: "	<< lib.getRVAToIAT()	<< std::endl
						<< "============================="			<< std::endl;

			// List the imported functions for the library
			const PEImportLibrary::IMPORTED_LIST& functions = lib.getImportedFunctionList();
			for (PEImportLibrary::IMPORTED_LIST::const_iterator it = functions.begin(); it != functions.end(); ++it)
			{
				// Imported function
				const PEImportedFunction& func = *it;

				std::cout << "\t[+]";

				// If the function has a name - print it out
				if (func.hasName())
					std::cout << "\t" << func.getName();
				// Otherwise, it is imported by ordinal
				else
					std::cout << "\t#" << func.getOrdinal();

				// Hint
				std::cout << "\tHint: " << func.getHint() << std::endl;
			}

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