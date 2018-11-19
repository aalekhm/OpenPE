#pragma once
#ifndef _M_X64
	#ifdef _DEBUG
		#pragma comment(lib, "../../OpenPE/lib/OpenPE.lib")
	#else
		#pragma comment(lib, "../../Release/OpenPE.lib")
	#endif
#else
	#ifdef _DEBUG
		#pragma comment(lib, "../../x64/Debug/OpenPE.lib")
	#else
		#pragma comment(lib, "../../x64/Release/OpenPE.lib")
	#endif	
#endif