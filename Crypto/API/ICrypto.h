#ifndef _ICRYPTO
#define _ICRYPTO

#include <vector>
#include <iostream>
#include "CryptoTypes.h"

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

	// AES Block Mode Types
	AES_ECB,
	AES_CBC,
	AES_CTR,

	// DES Block Mode Types
	DES_ECB,
	DES_CBC,
	TDES_ECB,
	TDES_CBC,
};


// Common crypto interface for different cipher schemes
class ICrypto {
	
public:
	// Encrypt vPlain into vCipher
	virtual CRYPTO_ERROR_CODES EncryptData(std::vector<u8> vPlain, std::vector<u8>& vCipher, std::vector<u8> vKey, std::vector<u8> vIV) = 0;
	// Decrypt vCipher into vPlain
	virtual CRYPTO_ERROR_CODES DecryptData(std::vector<u8> vPlain, std::vector<u8>& vCipher, std::vector<u8> vKey, std::vector<u8> vIV) = 0;
	// Retrieve block size for the cipher in bytes
	virtual uint GetBlockSize() = 0;

private:

};

// AES Block Cipher Schemes
class CryptoAES : ICrypto
{
public:
	CryptoAES() : m_nMode(CRYPTO_MODES::AES_ECB) {};

	// Init with requested encryption mode
	CRYPTO_ERROR_CODES Init(CRYPTO_MODES nMode = CRYPTO_MODES::AES_ECB);
	// Encrypt vPlain into vCipher
	CRYPTO_ERROR_CODES EncryptData(std::vector<u8> vPlain, std::vector<u8>& vCipher, std::vector<u8> vKey, std::vector<u8> vIV);
	// Decrypt vCipher into vPlain
	CRYPTO_ERROR_CODES DecryptData(std::vector<u8> vCipher, std::vector<u8>& vPlain, std::vector<u8> vKey, std::vector<u8> vIV);
	// Retrieve block size for the cipher in bytes
	uint GetBlockSize();

	// Perform a basic test for each mode of AES encryption supported
	static bool SelfTest(bool bPrintToConsole = false);

private:
	CRYPTO_ERROR_CODES Encrypt(const u8* pIn, size_t nBytesIn, u8* pOut, size_t nBytesOut, u8* pKey, size_t nKeyLength, u8* pIV, CRYPTO_MODES nMode);
	CRYPTO_ERROR_CODES Decrypt(const u8* pIn, size_t nBytesIn, u8* pOut, size_t nBytesOut, u8* pKey, size_t nKeyLength, u8* pIV, CRYPTO_MODES nMode);

	CRYPTO_MODES m_nMode;
};

/*
// DES Block Cipher Schemes
class CryptoDES : ICrypto
{

public:
	virtual bool Init() = 0;
	// Encrypt vPlain into vCipher
	virtual CRYPTO_ERROR_CODES EncryptData(std::vector<u8> vPlain, std::vector<u8>& vCipher, std::vector<u8> vKey, std::vector<u8> vIV) = 0;
	// Decrypt vCipher into vPlain
	virtual CRYPTO_ERROR_CODES DecryptData(std::vector<u8> vPlain, std::vector<u8>& vCipher, std::vector<u8> vKey, std::vector<u8> vIV) = 0;
	// Retrieve block size for the cipher in bytes
	virtual uint GetBlockSize() = 0;

private:
	virtual CRYPTO_ERROR_CODES Encrypt(const u8* pIn, const uint nBytesIn, u8* pOut, uint nBytesOut, const u8* pKey, int nMode);
	virtual CRYPTO_ERROR_CODES Decrypt(const u8* pIn, const uint nBytesIn, u8* pOut, uint nBytesOut, const u8* pKey, int nMode);
};

// DUKPT Block Cipher Schemes
class CryptoDUKPT : ICrypto
{
public:
	virtual bool Init() = 0;
	// Encrypt vPlain into vCipher
	virtual CRYPTO_ERROR_CODES EncryptData(std::vector<u8> vPlain, std::vector<u8> vKey, std::vector<u8>& vCipher, std::vector<u8> vIV) = 0;
	// Decrypt vCipher into vPlain
	virtual CRYPTO_ERROR_CODES DecryptData(std::vector<u8> vCipher, std::vector<u8> vKey, std::vector<u8>& vPlain, std::vector<u8> vIV) = 0;
	// Retrieve block size for the cipher in bytes
	virtual uint GetBlockSize() = 0;

private:
	virtual CRYPTO_ERROR_CODES Encrypt(const u8* pIn, const uint nBytesIn, u8* pOut, uint nBytesOut, const u8* pKey1, const u8* pKey2, const u8* pKey3, int nMode = NULL);
	virtual CRYPTO_ERROR_CODES Decrypt(const u8* pIn, const uint nBytesIn, u8* pOut, uint nBytesOut, const u8* pKey1, const u8* pKey2, const u8* pKey3, int nMode = NULL);
};
*/

#endif // _ICRYPTO