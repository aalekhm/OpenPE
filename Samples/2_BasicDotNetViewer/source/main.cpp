#include <iostream>
#include <fstream>
#include "OpenPE.h"
#include "../Samples/lib.h"

using namespace OpenPE;

int main(int argc, char* argv[])
{
	if (argc NOT_EQUAL_TO 2)
	{
		std::cout << "Usage: BasicGotNetViewer.exe PE_FILE" << std::endl;
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
		PEBase peImage(PEFactory::createPE(peFile, false));

		std::cout << "***** OpenPE *****" << std::hex << std::showbase << std::endl;
		if (NOT peImage.isDotNet())
		{
			std::cout << "Image is not .NET" << std::endl;
			return 0;
		}

		std::cout << "Reading Basic DOTNET info..." << std::hex << std::showbase << std::endl << std::endl;

		const PEBasicDotNetInfo peDotNetInfo(OpenPE::getBasicDotNetInfo(peImage));

		// Display .NET relevant information
		std::cout	<< "Major Runtime version: "	<< peDotNetInfo.getMajorRuntimeVersion() << std::endl
					<< "Minor Runtime version: "	<< peDotNetInfo.getMinorRuntimeVersion() << std::endl
					<< "Flags"						<< peDotNetInfo.getFlags() << std::endl
					<< "RVA of Resources"			<< peDotNetInfo.getRVAOfResources() << std::endl
					<< "RVA of MetaData"			<< peDotNetInfo.getRVAOfMetaData() << std::endl
					<< "Size of Resources"			<< peDotNetInfo.getSizeOfResources() << std::endl
					<< "Size of MetaData"			<< peDotNetInfo.getSizeOfMetaData() << std::endl;

		if (peDotNetInfo.isNativeEntryPoint())
			std::cout << "Entry Point RVA: ";
		else
			std::cout << "Entry Point Token: ";

		std::cout << peDotNetInfo.getEntryPointRVAOrToken() << std::endl;
	}
	catch (PEException& e)
	{
		std::cout << "Exception: " << e.what() << std::endl;
		return -1;
	}

	return 0;
}