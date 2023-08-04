#ifndef _ICRYPTO
#define _ICRYPTO

#include <vector>
#include <iostream>
#include "CryptoTypes.h"


// Common crypto interface for different cipher schemes
class ICrypto {
	
public:
	// Encrypt vPlain into vCipher
	virtual CRYPTO_ERROR_CODES EncryptData(u8Vec vPlain, u8Vec& vCipher, 
		u8Vec vKey, u8Vec vIV) = 0;
	// Decrypt vCipher into vPlain
	virtual CRYPTO_ERROR_CODES DecryptData(u8Vec vPlain, u8Vec& vCipher, 
		u8Vec vKey, u8Vec vIV) = 0;
	// Retrieve block size for the cipher in bytes
	virtual uint GetBlockSize() = 0;

private:

};


// AES Block Cipher Schemes
class CryptoAES : ICrypto
{
public:
	CryptoAES() : m_nMode(CRYPTO_MODES::AES_ECB) {}

	// Init with requested encryption mode
	CRYPTO_ERROR_CODES Init(CRYPTO_MODES nMode = CRYPTO_MODES::AES_ECB);
	// Encrypt vPlain into vCipher
	CRYPTO_ERROR_CODES EncryptData(u8Vec vPlain, u8Vec& vCipher, u8Vec vKey, 
		u8Vec vIV);
	// Decrypt vCipher into vPlain
	CRYPTO_ERROR_CODES DecryptData(u8Vec vCipher, u8Vec& vPlain, u8Vec vKey, 
		u8Vec vIV);
	// Retrieve block size for the cipher in bytes
	uint GetBlockSize();

	// Perform a basic test for each mode of AES encryption supported
	static bool SelfTest(bool bPrintToConsole = false);

private:
	CRYPTO_ERROR_CODES Encrypt(const u8* pIn, size_t nBytesIn, u8* pOut, 
		size_t nBytesOut, u8* pKey, size_t nKeyLength, u8* pIV, 
		CRYPTO_MODES nMode);
	CRYPTO_ERROR_CODES Decrypt(const u8* pIn, size_t nBytesIn, u8* pOut, 
		size_t nBytesOut, u8* pKey, size_t nKeyLength, u8* pIV, 
		CRYPTO_MODES nMode);

	CRYPTO_MODES m_nMode;
};
                                                                                

// TDES Block Cipher Schemes
class CryptoTDES : ICrypto
{
public:
	CryptoTDES() : m_nMode(CRYPTO_MODES::TDES_ECB) {}

	// Init with requested encryption mode
	CRYPTO_ERROR_CODES Init(CRYPTO_MODES nMode = CRYPTO_MODES::TDES_ECB);
	// Encrypt vPlain into vCipher
	CRYPTO_ERROR_CODES EncryptData(u8Vec vPlain, u8Vec& vCipher, u8Vec vKey, 
		u8Vec vIV);
	// Decrypt vCipher into vPlain
	CRYPTO_ERROR_CODES DecryptData(u8Vec vPlain, u8Vec& vCipher, u8Vec vKey, 
		u8Vec vIV);
	// Retrieve block size for the cipher in bytes
	uint GetBlockSize();

	// Perform a basic test for each mode of DES encryption supported
	static bool SelfTest(bool bPrintToConsole = false);

private:
	CRYPTO_ERROR_CODES Encrypt(const u8* pIn, size_t nBytesIn, u8* pOut, 
		size_t nBytesOut, u8* pKey, size_t nKeyLength, u8* pIV, 
		CRYPTO_MODES nMode);
	CRYPTO_ERROR_CODES Decrypt(const u8* pIn, size_t nBytesIn, u8* pOut, 
		size_t nBytesOut, u8* pKey, size_t nKeyLength, u8* pIV, 
		CRYPTO_MODES nMode);

	CRYPTO_MODES m_nMode;
};

/*
// DUKPT Block Cipher Schemes
class CryptoDUKPT : ICrypto
{
public:
	virtual bool Init() = 0;
	// Encrypt vPlain into vCipher
	virtual CRYPTO_ERROR_CODES EncryptData(u8Vec vPlain, u8Vec vKey, u8Vec& vCipher, u8Vec vIV) = 0;
	// Decrypt vCipher into vPlain
	virtual CRYPTO_ERROR_CODES DecryptData(u8Vec vCipher, u8Vec vKey, u8Vec& vPlain, u8Vec vIV) = 0;
	// Retrieve block size for the cipher in bytes
	virtual uint GetBlockSize() = 0;

private:
	virtual CRYPTO_ERROR_CODES Encrypt(const u8* pIn, const uint nBytesIn, u8* pOut, uint nBytesOut, const u8* pKey1, const u8* pKey2, const u8* pKey3, int nMode = NULL);
	virtual CRYPTO_ERROR_CODES Decrypt(const u8* pIn, const uint nBytesIn, u8* pOut, uint nBytesOut, const u8* pKey1, const u8* pKey2, const u8* pKey3, int nMode = NULL);
};
*/

#endif // _ICRYPTO