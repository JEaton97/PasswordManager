#pragma once

#include <cstdint>
#include <vector>

typedef uint8_t u8;
typedef uint32_t uint;

typedef std::vector<u8> u8Vec;


enum class CRYPTO_ERROR_CODES {
	CRYPT_OK,
	CRYPT_ERROR_NOT_IMPLEMENTED,
	CRYPT_ERROR_MBEDCRYPTO,
	CRYPT_ERROR_BAD_INPUT,
	CRYPT_ERROR_BLOCK_SIZE,
	// ...
};


enum class CRYPTO_MODES {
	NONE,

	// AES Mode Types
	AES_ECB,
	AES_CBC,
	AES_CTR,

	// TDES Mode Types
	TDES_ECB,
	TDES_CBC,
};