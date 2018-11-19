#include <iostream>
#include <fstream>
#include <OpenPE.h>
#include "../Samples/lib.h"

using namespace OpenPE;

int main(int argc, char* argv[])
{
	if (argc NOT_EQUAL_TO 2)
	{
		std::cout << "Usage: BasicFileViewer.exe PE_FILE" << std::endl;
		return 0;
	}

	std::ifstream peFile(argv[1], std::ios::in | std::ios::binary);
	if (NOT peFile)
	{
		std::cout << "Unable to open file:" << argv[1] << std::endl;
		return -1;
	}

	try
	{
		PEBase peImage(PEFactory::createPE(peFile));

		std::cout << "***** OpenPE *****"			<< std::hex << std::showbase								<< std::endl;
		std::cout << "PE File Type: "				<< (peImage.getPEType() == PEType::PEType_32 ? "PE32 (PE)" : "PE64 (PE+)") << std::endl;
		
		// Calculate Checksum
		std::cout << "Calculated Checksum: "		<< OpenPE::calculateChecksum(peFile)						<< std::endl;
		// Real Stored Checksum
		std::cout << "Stored Checksum : "			<< peImage.getChecksum()									<< std::endl;

		// Characteristics
		std::cout << "Characteristics: "			<< peImage.getCharacteristics()								<< std::endl;

		// Entry Point
		std::cout << "Entry Point: "				<< peImage.getEntryPoint()									<< std::endl;

		// File & Section alignment
		std::cout << "File Alignment: "				<< peImage.getFileAlignment()								<< std::endl;
		std::cout << "Section  Alignment: "			<< peImage.getSectionAlignment()							<< std::endl;

		// Image Bsse
		std::cout << "Image Base: "					<< peImage.getImageBase64()									<< std::endl;

		std::cout << "Subsystem: "					<< peImage.getSubsystem()									<< std::endl;
		std::cout << "Image Base: "					<< (peImage.isConsole()					? "YES" : "NO")		<< std::endl;
		std::cout << "Is Windows GUI: "				<< (peImage.isGui()						? "YES" : "NO")		<< std::endl;

		// Data Directories
		std::cout << "Has Bound Import: "			<< (peImage.hasBoundImport()			? "YES" : "NO")		<< std::endl;
		std::cout << "Has Config: "					<< (peImage.hasConfig()					? "YES" : "NO")		<< std::endl;
		std::cout << "Has Debug "					<< (peImage.hasDebug()					? "YES" : "NO")		<< std::endl;
		std::cout << "Has DelayImport: "			<< (peImage.hasDelayImport()			? "YES" : "NO")		<< std::endl;
		std::cout << "Has Exception Directory: "	<< (peImage.hasExceptionDirectory()		? "YES" : "NO")		<< std::endl;
		std::cout << "Has Exports: "				<< (peImage.hasExports()				? "YES" : "NO")		<< std::endl;
		std::cout << "Has Imports: "				<< (peImage.hasImports()				? "YES" : "NO")		<< std::endl;
		std::cout << "Has Reloc: "					<< (peImage.hasReloc()					? "YES" : "NO")		<< std::endl;
		std::cout << "Has Resources: "				<< (peImage.hasResources()				? "YES" : "NO")		<< std::endl;
		std::cout << "Has Security: "				<< (peImage.hasSecurity()				? "YES" : "NO")		<< std::endl;
		std::cout << "Has TLS: "					<< (peImage.hasTLS()					? "YES" : "NO")		<< std::endl;
		std::cout << "Is .NET: "					<< (peImage.isDotNet()					? "YES" : "NO")		<< std::endl;

		bool b = true;
	}
	catch (PEException& e)
	{
		std::cout << "Exception: " << e.what() << std::endl;
		return -1;
	}

	return 0;
}