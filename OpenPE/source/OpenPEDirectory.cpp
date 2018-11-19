#include "OpenPEDirectory.h"

namespace OpenPE
{
	PEImageDirectory::PEImageDirectory()
	: m_iRVA(0)
	, m_iSize(0)
	{}

	PEImageDirectory::PEImageDirectory(uint32_t iRVA, uint32_t iSize)
	: m_iRVA(iRVA)
	, m_iSize(iSize)
	{}

	// Returns RVA
	uint32_t PEImageDirectory::getRVA() const
	{
		return m_iRVA;
	}

	// Returns Size
	uint32_t PEImageDirectory::getSize() const
	{
		return m_iSize;
	}

	// Sets RVA
	void PEImageDirectory::setRVA(uint32_t iRVA)
	{
		m_iRVA = iRVA;
	}

	// Sets Size
	void PEImageDirectory::setSize(uint32_t iSize)
	{
		m_iSize = iSize;
	}
}