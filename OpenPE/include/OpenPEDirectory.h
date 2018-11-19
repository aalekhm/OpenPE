#pragma once

#include <stdint.h>

namespace OpenPE
{
	// Class representing image directory data
	class PEImageDirectory
	{
		public:
			// Default Constructor
			PEImageDirectory();

			// Constructor from data
			PEImageDirectory(uint32_t iRVA, uint32_t iSize);

			// Returns RVA
			uint32_t		getRVA() const;

			// Returns Size
			uint32_t		getSize() const;

			// Sets RVA
			void			setRVA(uint32_t iRVA);

			// Sets Size
			void			setSize(uint32_t iSize);
		private:
			uint32_t		m_iRVA;
			uint32_t		m_iSize;
	};
}