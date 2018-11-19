#pragma once
#include "OpenPEBase.h"

namespace OpenPE
{
	class PEFactory
	{
		public:
			static PEBase createPE(std::istream& fStream, bool bDebugRawData = true);
	};
}