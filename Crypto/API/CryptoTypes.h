#pragma once

#include <cstdint>
#include <vector>

typedef uint8_t u8;
typedef uint32_t uint;

typedef std::vector<u8> u8Vec;


enum class CRYPTO_ERROR_CODES {
	CRYPT_OK,
	CRYPT_ERROR_NOT_IMPLEMENTED,
	// Encryption/Decryption Error Codes
	CRYPT_ERROR_MBEDCRYPTO,		// Error occurred in MBEDCRYPTO library
	CRYPT_ERROR_ARGON2,			// Error occurred in ARGON2 library
	CRYPT_ERROR_BAD_INPUT,		// Bad Input
	CRYPT_ERROR_BLOCK_SIZE,		// Input not padded correctly
	// CryptoKey Error Codes
	CRYPT_ERROR_FILE_IO,		// File IO error
	CRYPT_ERROR_FILE_CORRUPTED,	// File corruption or tamper detected
	CRYPT_ERROR_FILE_SIZE,		// Unexpected file size
};


enum class CRYPTO_MODES {
	BEGIN,	// Dummy value for iteration

	// AES Mode Types
	AES_ECB,
	AES_CBC,
	AES_CTR,

	// TDES Mode Types
	TDES_ECB,
	TDES_CBC,

	LAST	// Dummy value for iteration
};

const char* GetCryptoModeStr(CRYPTO_MODES nMode);


enum class HASH_MODES {
	BEGIN,	// Dummy value for iteration

	// SHA Modes
	SHA224,
	SHA256,
	SHA384,
	SHA512,

	// Argon2 Modes
	ARGON2I,
	ARGON2D,
	ARGON2ID,

	LAST	// Dummy value for iteration
};

const char* GetHashModeStr(HASH_MODES nMode);