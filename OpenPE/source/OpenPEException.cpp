#include "OpenPEException.h"

namespace OpenPE
{
	PEException::PEException(const char* pExceptionString, PEException_ID pe_eid /* = PEException_ID::PEEXCEPTION_UNKNOWN_ERROR */)
	: std::runtime_error(pExceptionString)
	, m_ePEExceptionID(pe_eid)
	{
	}

	PEException::PEException(const std::string& pExceptionString, PEException_ID pe_eid /* = PEException_ID::PEEXCEPTION_UNKNOWN_ERROR */)
	: std::runtime_error(pExceptionString)
	, m_ePEExceptionID(pe_eid)
	{
	}

	PEException::PEException_ID	PEException::getId() const
	{
		return m_ePEExceptionID;
	}
}

