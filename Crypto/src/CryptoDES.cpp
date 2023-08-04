#include <iostream>
#include "ICrypto.h"
#include "mbedtls/des.h"

#define N_BLOCK 8

CRYPTO_ERROR_CODES CryptoTDES::Init(
	CRYPTO_MODES nMode /* = CRYPTO_MODES::TDES_ECB */)
{
	switch (nMode)
	{
	case CRYPTO_MODES::TDES_ECB:
	case CRYPTO_MODES::TDES_CBC:
		break;
	default:
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_BAD_INPUT;
	}
	m_nMode = nMode;
	return CRYPTO_ERROR_CODES::CRYPT_OK;
}

CRYPTO_ERROR_CODES CryptoTDES::EncryptData(u8Vec vPlain, u8Vec& vCipher, 
	u8Vec vKey, u8Vec vIV)
{
	// Make sure vIV is correct size or empty
	if (vIV.size() != 0 && vIV.size() != N_BLOCK)
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_BAD_INPUT;

	// Resize output vector. For TDES, input size == output size
	vCipher.resize(vPlain.size());

	return Encrypt(&vPlain[0], vPlain.size(), &vCipher[0], vCipher.size(), 
		&vKey[0], vKey.size(), vIV.size() == 0 ? nullptr : &vIV[0], m_nMode);
}

CRYPTO_ERROR_CODES CryptoTDES::DecryptData(u8Vec vCipher, u8Vec& vPlain, 
	u8Vec vKey, u8Vec vIV)
{
	// Make sure vIV is correct size or empty
	if (vIV.size() != 0 && vIV.size() != N_BLOCK)
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_BAD_INPUT;

	// Resize output vector. For TDES, input size == output size
	vPlain.resize(vCipher.size());

	return Decrypt(&vCipher[0], vCipher.size(), &vPlain[0], vPlain.size(), 
		&vKey[0], vKey.size(), vIV.size() == 0 ? nullptr : &vIV[0], m_nMode);
}

uint CryptoTDES::GetBlockSize()
{
	return N_BLOCK;
}

CRYPTO_ERROR_CODES CryptoTDES::Encrypt(const u8* pIn, size_t nBytesIn, u8* pOut,
	size_t nBytesOut, u8* pKey, size_t nKeyLength, u8* pIV, CRYPTO_MODES nMode)
{
	// Parameter checking
	switch (nMode)
	{
	case CRYPTO_MODES::TDES_ECB:
	case CRYPTO_MODES::TDES_CBC:
		break;
	default:
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_BAD_INPUT;
	}

	nKeyLength *= 8;	// Convert from bytes to bits
	switch (nKeyLength)
	{
	case 128:	// TDES - 2 key
	case 192:	// TDES - 3 key
		break;
	default:
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_BAD_INPUT;
	}

	if (nBytesIn % N_BLOCK != 0)
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_BAD_INPUT;

	// Initialize context and buffers
	mbedtls_des3_context _ctx;
	mbedtls_des3_init(&_ctx);
	switch (nKeyLength)
	{
	case 128:	// 2-key
		if (mbedtls_des3_set2key_enc(&_ctx, pKey) != 0)
			return CRYPTO_ERROR_CODES::CRYPT_ERROR_MBEDCRYPTO;
		break;
	case 192:	// 3-key
		if (mbedtls_des3_set3key_enc(&_ctx, pKey) != 0)
			return CRYPTO_ERROR_CODES::CRYPT_ERROR_MBEDCRYPTO;
		break;
	}	

	u8 _iv[N_BLOCK] = {};

	// Use IV provided otherwise leave as zero default
	if (pIV)
		memcpy(_iv, pIV, N_BLOCK);

	// Encrypt
	switch (nMode)
	{
	case CRYPTO_MODES::TDES_ECB:
	{
		uint _nLength = (uint)nBytesIn;
		while (_nLength > 0)
		{
			if (mbedtls_des3_crypt_ecb(&_ctx, pIn, pOut) != 0)
				return CRYPTO_ERROR_CODES::CRYPT_ERROR_MBEDCRYPTO;
			pIn += N_BLOCK;
			pOut += N_BLOCK;	// NOTE: Using blocks of size 8 here
			_nLength -= N_BLOCK;
		}
	} break;
	case CRYPTO_MODES::TDES_CBC:
	{
		if (mbedtls_des3_crypt_cbc(&_ctx, MBEDTLS_DES_ENCRYPT, nBytesIn, _iv, 
			pIn, pOut))
			return CRYPTO_ERROR_CODES::CRYPT_ERROR_MBEDCRYPTO;
	} break;
	}

	// Copy out IV
	if (pIV)
		memcpy(pIV, _iv, N_BLOCK);

	return CRYPTO_ERROR_CODES::CRYPT_OK;
}

CRYPTO_ERROR_CODES CryptoTDES::Decrypt(const u8* pIn, size_t nBytesIn, u8* pOut,
	size_t nBytesOut, u8* pKey, size_t nKeyLength, u8* pIV, CRYPTO_MODES nMode)
{
	// Parameter checking
	switch (nMode)
	{
	case CRYPTO_MODES::TDES_ECB:
	case CRYPTO_MODES::TDES_CBC:
		break;
	default:
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_BAD_INPUT;
	}

	nKeyLength *= 8;	// Convert from bytes to bits
	switch (nKeyLength)
	{
	case 128:	// TDES - 2 key
	case 192:	// TDES - 3 key
		break;
	default:
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_BAD_INPUT;
	}

	if (nBytesIn % N_BLOCK != 0)
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_BAD_INPUT;

	// Initialize context and buffers
	mbedtls_des3_context _ctx;
	mbedtls_des3_init(&_ctx);
	switch (nKeyLength)
	{
	case 128:	// 2-key
		if (mbedtls_des3_set2key_dec(&_ctx, pKey) != 0)
			return CRYPTO_ERROR_CODES::CRYPT_ERROR_MBEDCRYPTO;
		break;
	case 192:	// 3-key
		if (mbedtls_des3_set3key_dec(&_ctx, pKey) != 0)
			return CRYPTO_ERROR_CODES::CRYPT_ERROR_MBEDCRYPTO;
		break;
	}

	u8 _iv[N_BLOCK] = {};

	// Use IV provided otherwise leave as zero default
	if (pIV)
		memcpy(_iv, pIV, N_BLOCK);

	// Encrypt
	switch (nMode)
	{
	case CRYPTO_MODES::TDES_ECB:
	{
		uint _nLength = (uint)nBytesIn;
		while (_nLength > 0)
		{
			if (mbedtls_des3_crypt_ecb(&_ctx, pIn, pOut) != 0)
				return CRYPTO_ERROR_CODES::CRYPT_ERROR_MBEDCRYPTO;
			pIn += N_BLOCK;
			pOut += N_BLOCK;	// NOTE: Using blocks of size 8 here
			_nLength -= N_BLOCK;
		}
	} break;
	case CRYPTO_MODES::TDES_CBC:
	{
		if (mbedtls_des3_crypt_cbc(&_ctx, MBEDTLS_DES_DECRYPT, nBytesIn, _iv, 
			pIn, pOut))
			return CRYPTO_ERROR_CODES::CRYPT_ERROR_MBEDCRYPTO;
	} break;
	}

	// Copy out IV
	if (pIV)
		memcpy(pIV, _iv, N_BLOCK);

	return CRYPTO_ERROR_CODES::CRYPT_OK;
}

// Helper function for self test to reduce code duplication
bool RunTest(CryptoTDES* pTDES, u8Vec vPlain, u8Vec& vCipher, u8Vec vKey, u8Vec 
	vIV, CRYPTO_MODES nMode, bool bPrintToConsole = false);

bool CryptoTDES::SelfTest(bool bPrintToConsole /* = false */)
{
	bool _bSuccess = true;
	CryptoTDES _tdes;

	// NOTE: Validation vectors pulled from https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers

	// ECB, 128-bit key (2-key)
	{
		u8Vec _key = 
		{ 0xcd, 0x3d, 0x9b, 0xf7, 0x2f, 0x8c, 0x8a, 0xb5, 
		  0xfe, 0xe6, 0x73, 0x34, 0x31, 0x1c, 0xa4, 0x62 };
		u8Vec _plain = 
		{ 0x2f, 0x2a, 0x36, 0x1c, 0x8e, 0x14, 0x5d, 0xc0, 
		  0xa7, 0x4a, 0x1b, 0xdb, 0x7c, 0xa9, 0x29, 0xc3, 
		  0x38, 0x14, 0x4d, 0x89, 0x13, 0x5b, 0x50, 0xa7 };
		u8Vec _cipher = 
		{ 0x7f, 0x1f, 0xd3, 0x2b, 0x36, 0x90, 0x05, 0x4b, 
		  0xfa, 0x1b, 0x17, 0x35, 0x15, 0x79, 0x33, 0x80, 
		  0x99, 0xff, 0xa8, 0x4f, 0xea, 0x16, 0x8c, 0x6b };
		u8Vec _iv = {};

		if (!RunTest(&_tdes, _plain, _cipher, _key, _iv, CRYPTO_MODES::TDES_ECB, 
			bPrintToConsole))
			_bSuccess = false;
	}

	// ECB, 192-bit key (3-key)
	{
		u8Vec _key = 
		{ 0x02, 0x20, 0x04, 0x83, 0xba, 0x6d, 0xf7, 0x67, 
		  0x5d, 0xea, 0x40, 0x73, 0xb0, 0x2a, 0x1c, 0x5b, 
		  0x85, 0x02, 0x54, 0x23, 0xe5, 0xc4, 0xa4, 0xb5 };
		u8Vec _plain = 
		{ 0x30, 0x0c, 0xe0, 0x17, 0x8d, 0x4d, 0x54, 0x56, 
		  0x40, 0x24, 0x3b, 0x9d, 0xb8, 0x18, 0x90, 0x4a, 
		  0xe9, 0x17, 0x19, 0x5d, 0xe7, 0xbb, 0x9a, 0xda };
		u8Vec _cipher = 
		{ 0x8f, 0x83, 0x4b, 0x37, 0xf7, 0x40, 0x4e, 0x5e, 
		  0xdb, 0x32, 0xd1, 0x0b, 0x17, 0x5c, 0x28, 0xac, 
		  0x6d, 0x94, 0x3b, 0x19, 0xc2, 0x59, 0x83, 0x49 };
		u8Vec _iv = {};
	
		if (!RunTest(&_tdes, _plain, _cipher, _key, _iv, CRYPTO_MODES::TDES_ECB, 
			bPrintToConsole))
			_bSuccess = false;
	}

	// CBC, 128-bit key (2-key)
	{
		u8Vec _key = 
		{ 0x76, 0x64, 0x52, 0x49, 0x5b, 0xbf, 0x79, 0x7c, 
		  0x0e, 0x57, 0xd6, 0x38, 0x9b, 0x52, 0x3d, 0x3b };
		u8Vec _plain = 
		{ 0xcb, 0x90, 0xfc, 0xa4, 0x13, 0xc8, 0x84, 0x39, 
		  0x00, 0x77, 0x08, 0x4c, 0xd8, 0x66, 0xb6, 0xc8, 
		  0x15, 0x0f, 0x4f, 0x5d, 0x44, 0xc6, 0xd6, 0x22 };
		u8Vec _cipher = 
		{ 0xa8, 0x35, 0xaf, 0xd4, 0xda, 0xd3, 0x76, 0xd6, 
		  0x11, 0xbe, 0x4f, 0xc1, 0x28, 0x2d, 0x1e, 0x3e, 
		  0x36, 0xb3, 0xbe, 0x08, 0x1b, 0x7c, 0x3a, 0x4e };
		u8Vec _iv = 
		{ 0x03, 0x49, 0x76, 0x24, 0xec, 0xcc, 0x76, 0xc7 };

		if (!RunTest(&_tdes, _plain, _cipher, _key, _iv, CRYPTO_MODES::TDES_CBC, 
			bPrintToConsole))
			_bSuccess = false;
	}

	// CBC, 192-bit key (3-key)
	{
		u8Vec _key = 
		{ 0x13, 0x4c, 0xb3, 0xef, 0xe6, 0x2a, 0x4a, 0xd5, 
		  0x52, 0xcb, 0x85, 0xa1, 0x64, 0xfe, 0xe6, 0xb9, 
		  0x64, 0xa1, 0x26, 0x9b, 0x19, 0x3d, 0x68, 0xc4 };
		u8Vec _plain = 
		{ 0x1b, 0x73, 0x5b, 0x05, 0x57, 0x25, 0x5a, 0x0e, 
		  0x6d, 0x8d, 0x67, 0x58, 0x79, 0xe7, 0x20, 0x1c, 
		  0xa3, 0x4c, 0x87, 0x61, 0xa1, 0x29, 0xa9, 0x14 };
		u8Vec _cipher = 
		{ 0x2f, 0x1a, 0xc7, 0xee, 0x14, 0x14, 0xaf, 0x15, 
		  0x58, 0x7c, 0xb2, 0xc5, 0x40, 0x40, 0x12, 0x94,
		  0x02, 0x8e, 0x1e, 0x39, 0xd1, 0xcf, 0x2f, 0x67 };
		u8Vec _iv = 
		{ 0x0f, 0xa3, 0x11, 0xf9, 0x9e, 0xc5, 0x7b, 0x86 };
	
		if (!RunTest(&_tdes, _plain, _cipher, _key, _iv, CRYPTO_MODES::TDES_CBC, 
			bPrintToConsole))
			_bSuccess = false;
	}

	return _bSuccess;
}

bool RunTest(CryptoTDES* pTDES, u8Vec vPlain, u8Vec& vCipher, u8Vec vKey, 
	u8Vec vIV, CRYPTO_MODES nMode, bool bPrintToConsole /* = false */)
{
	bool _bSuccess = true;
	CRYPTO_ERROR_CODES _nRC;
	u8Vec _encrypted, _decrypted;

	std::string _strModeName;
	std::string _strNumKeys;
	switch (nMode)
	{
	case CRYPTO_MODES::TDES_ECB:
		_strModeName = "TDES_ECB";
		break;
	case CRYPTO_MODES::TDES_CBC:
		_strModeName = "TDES_CBC";
		break;
	default:
		_strModeName = "TDES_UNKNOWN";
		break;
	}
	switch (vKey.size() * 8)
	{
	case 128:
		_strNumKeys = "2-key ";
		break;
	case 192:
		_strNumKeys = "3-key ";
		break;
	default:
		_strNumKeys = "?-key ";
		break;
	}

	pTDES->Init(nMode);

	// Encryption
	_nRC = pTDES->EncryptData(vPlain, _encrypted, vKey, vIV);
	if (CRYPTO_ERROR_CODES::CRYPT_OK != _nRC)
	{
		if (bPrintToConsole)
			std::cout << "CryptoDES SelfTest (" << _strNumKeys << _strModeName
				<< ") : FAIL - Encryption returned " << (int)_nRC << std::endl;
		_bSuccess = false;
	}
	if (memcmp(&vCipher[0], &_encrypted[0], _encrypted.size()) != 0)
	{
		if (bPrintToConsole)
			std::cout << "CryptoDES SelfTest (" << _strNumKeys << _strModeName
				<< ") : FAIL - Encrypted output does not match expected" 
				<< std::endl;
		_bSuccess = false;
	}

	// Decryption
	_nRC = pTDES->DecryptData(vCipher, _decrypted, vKey, vIV);
	if (CRYPTO_ERROR_CODES::CRYPT_OK != _nRC)
	{
		if (bPrintToConsole)
			std::cout << "CryptoDES SelfTest (" << _strNumKeys << _strModeName
				<< ") : FAIL - Decryption returned " << (int)_nRC << std::endl;
		_bSuccess = false;
	}
	if (memcmp(&vPlain[0], &_decrypted[0], _decrypted.size()) != 0)
	{
		if (bPrintToConsole)
			std::cout << "CryptoDES SelfTest (" << _strNumKeys << _strModeName
			<< ") : FAIL - Decrypted output does not match expected"
			<< std::endl;
		_bSuccess = false;
	}

	if (_bSuccess && bPrintToConsole)
		std::cout << "CryptoDES SelfTest (" << _strNumKeys << _strModeName
		<< ") : PASS" << std::endl << std::endl;

	return _bSuccess;
}