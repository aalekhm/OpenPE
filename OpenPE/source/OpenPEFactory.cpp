#include "OpenPEFactory.h"
#include "OpenPEPropertiesGeneric.h"
#include "OpenPEBase.h"
#include "OpenPEStructures.h"

namespace OpenPE
{
	PEBase PEFactory::createPE(std::istream& fStream, bool bDebugRawData /*= true*/)
	{
		return (PEBase::getPEType(fStream) == PEType_32)
				? PEBase(fStream, PEProperties32(), bDebugRawData)
				: PEBase(fStream, PEProperties64(), bDebugRawData);
	}
}