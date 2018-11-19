#pragma once
#include <istream>
#include <stdint.h>

namespace OpenPE
{
	class PEUtils
	{
		public:
			static std::streamoff	getFileSize(std::istream& iFileStreamIn);

			// Helper function to determine if number is power of 2
			template<typename T>
			static inline bool isPowerOf2(T x)
			{
				return NOT(x & (x - 1));
			}

			// Helper function to align number up
			template<typename T>
			static inline T alignUp(T x, uint32_t iAlign)
			{
				return (x & static_cast<T>(iAlign - 1)) ? alignDown(x, iAlign) + static_cast<T>(iAlign) : x;
			}

			// Helper function to align number down
			template<typename T>
			static inline T alignDown(T x, uint32_t iAlign)
			{
				return x & ~(static_cast<T>(iAlign)-1);
			}

			// Checks if SUM of two unsigned integers if SAFE i.e no overflow occurs.
			static inline bool isSumSafe(uint32_t x1, uint32_t x2)
			{
				return x1 <= static_cast<uint32_t>(-1) - x2;
			}

			static const uint32_t TWO_GB = 0x80000000;
			static const uint32_t MAX_DWORD = 0xFFFF0000;
			static const uint32_t MAX_WORD = 0x0000FFFF;
	};
}