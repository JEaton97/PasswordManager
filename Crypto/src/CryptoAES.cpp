#include "ICrypto.h"
#include "mbedtls/aes.h"

#include <iostream>
#ifdef __GNUC__
#include <cstring>
#endif


#define N_ROW 4
#define N_COL 4
#define N_BLOCK (N_ROW * N_COL)

CRYPTO_ERROR_CODES CryptoAES::Init(
	CRYPTO_MODES nMode /* = CRYPTO_MODES::AES_ECB */)
{
	switch (nMode)
	{
	case CRYPTO_MODES::AES_ECB:
	case CRYPTO_MODES::AES_CBC:
	case CRYPTO_MODES::AES_CTR:
		break;
	default:
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_BAD_INPUT;
	}
	m_nMode = nMode;
	return CRYPTO_ERROR_CODES::CRYPT_OK;
}

// Encrypt vPlain into vCipher
CRYPTO_ERROR_CODES CryptoAES::EncryptData(u8Vec vPlain, u8Vec& vCipher, 
	u8Vec vKey, u8Vec vIV)
{
	// Make sure vIV is correct size or empty
	if (vIV.size() != 0 && vIV.size() != N_BLOCK)
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_BAD_INPUT;

	// Resize output vector. For AES, input size == output size
	vCipher.resize(vPlain.size());

	return Encrypt(&vPlain[0], vPlain.size(), &vCipher[0], vCipher.size(), 
		&vKey[0], vKey.size(), vIV.size() == 0 ? nullptr : &vIV[0], m_nMode);
}

// Decrypt vCipher into vPlain
CRYPTO_ERROR_CODES CryptoAES::DecryptData(u8Vec vCipher, u8Vec& vPlain, 
	u8Vec vKey, u8Vec vIV)
{
	// Make sure vIV is correct size or empty
	if (vIV.size() != 0 && vIV.size() != N_BLOCK)
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_BAD_INPUT;

	// Resize output vector. For AES, input size == output size
	vPlain.resize(vCipher.size());

	return Decrypt(&vCipher[0], vCipher.size(), &vPlain[0], vPlain.size(), 
		&vKey[0], vKey.size(), vIV.size() == 0 ? nullptr : &vIV[0], m_nMode);
}

// Retrieve block size for the cipher in bytes
uint CryptoAES::GetBlockSize()
{
	return N_BLOCK;
}

CRYPTO_ERROR_CODES CryptoAES::Encrypt(const u8* pIn, size_t nBytesIn, u8* pOut, 
	size_t nBytesOut, u8* pKey, size_t nKeyLength, u8* pIV, CRYPTO_MODES nMode)
{
	// Parameter checking
	switch (nMode)
	{
	case CRYPTO_MODES::AES_ECB:
	case CRYPTO_MODES::AES_CBC:
		break;
	case CRYPTO_MODES::AES_CTR:
		if (pIV == nullptr)
			// Don't allow zero IV for CTR since it is used as the nonce counter
			return CRYPTO_ERROR_CODES::CRYPT_ERROR_BAD_INPUT;
		break;
	default:
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_BAD_INPUT;
	}

	nKeyLength *= 8;	// Convert from bytes to bits
	switch (nKeyLength)
	{
	case 128:
	case 192:
	case 256:
		break;
	default:
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_BAD_INPUT;
	}

	if (nMode != CRYPTO_MODES::AES_CTR && ((nBytesIn % N_BLOCK) != 0))
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_BAD_INPUT;


	// Initialize context and buffers
	mbedtls_aes_context _ctx;
	mbedtls_aes_init(&_ctx);
	if (mbedtls_aes_setkey_enc(&_ctx, pKey, (uint)nKeyLength) != 0)
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_MBEDCRYPTO;

	u8 _strmBlock[N_BLOCK] = {};
	u8 _iv[N_BLOCK] = {};
	size_t _ncOff = 0;

	// Use IV provided otherwise leave as zero default
	if (pIV)
		memcpy(_iv, pIV, N_BLOCK);

	// Encrypt
	switch (nMode)
	{
	case CRYPTO_MODES::AES_ECB:
	{
		uint _nLength = (uint)nBytesIn;
		while (_nLength > 0)
		{
			if (mbedtls_aes_crypt_ecb(&_ctx, MBEDTLS_AES_ENCRYPT, pIn, pOut) 
				!= 0)
				return CRYPTO_ERROR_CODES::CRYPT_ERROR_MBEDCRYPTO;
			pIn += N_BLOCK;
			pOut += N_BLOCK;
			_nLength -= N_BLOCK;
		}
	} break;
	case CRYPTO_MODES::AES_CBC:
	{
		if (mbedtls_aes_crypt_cbc(&_ctx, MBEDTLS_AES_ENCRYPT, nBytesIn, _iv, 
			pIn, pOut) != 0)
			return CRYPTO_ERROR_CODES::CRYPT_ERROR_MBEDCRYPTO;
	} break;
	case CRYPTO_MODES::AES_CTR:
	{
		if (mbedtls_aes_crypt_ctr(&_ctx, nBytesIn, &_ncOff, _iv, _strmBlock, 
			pIn, pOut) != 0)
			return CRYPTO_ERROR_CODES::CRYPT_ERROR_MBEDCRYPTO;
	} break;
	}

	// Copy out IV
	if (pIV)
		memcpy(pIV, _iv, N_BLOCK);

	return CRYPTO_ERROR_CODES::CRYPT_OK;
}

CRYPTO_ERROR_CODES CryptoAES::Decrypt(const u8* pIn, size_t nBytesIn, u8* pOut, 
	size_t nBytesOut, u8* pKey, size_t nKeyLength, u8* pIV, CRYPTO_MODES nMode)
{
	// Parameter checking
	switch (nMode)
	{
	case CRYPTO_MODES::AES_ECB:
	case CRYPTO_MODES::AES_CBC:
		break;
	case CRYPTO_MODES::AES_CTR:
		// CTR decryption is same as encryption
		return Encrypt(pIn, nBytesIn, pOut, nBytesOut, pKey, nKeyLength, pIV, 
			nMode);
	default:
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_BAD_INPUT;
	}

	nKeyLength *= 8;	// Convert from bytes to bits
	switch (nKeyLength)
	{
	case 128:
	case 192:
	case 256:
		break;
	default:
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_BAD_INPUT;
	}

	if (nMode != CRYPTO_MODES::AES_CTR && ((nBytesIn % N_BLOCK) != 0))
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_BAD_INPUT;


	// Initialize context and buffers
	mbedtls_aes_context _ctx;
	if (mbedtls_aes_setkey_dec(&_ctx, pKey, (uint)nKeyLength) != 0)
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_MBEDCRYPTO;

	u8 _strmBlock[N_BLOCK] = {};
	u8 _iv[N_BLOCK] = {};
	size_t _ncOff = 0;

	// Use IV provided otherwise leave as zero default
	if (pIV)
		memcpy(_iv, pIV, N_BLOCK);

	// Encrypt
	switch (nMode)
	{
	case CRYPTO_MODES::AES_ECB:
	{
		uint _nLength = (uint)nBytesIn;
		while (_nLength > 0)
		{
			if (mbedtls_aes_crypt_ecb(&_ctx, MBEDTLS_AES_DECRYPT, pIn, pOut) 
				!= 0)
				return CRYPTO_ERROR_CODES::CRYPT_ERROR_MBEDCRYPTO;
			pIn += N_BLOCK;
			pOut += N_BLOCK;
			_nLength -= N_BLOCK;
		}
	} break;
	case CRYPTO_MODES::AES_CBC:
	{
		if (mbedtls_aes_crypt_cbc(&_ctx, MBEDTLS_AES_DECRYPT, nBytesIn, _iv, 
			pIn, pOut) != 0)
			return CRYPTO_ERROR_CODES::CRYPT_ERROR_MBEDCRYPTO;
	} break;
	case CRYPTO_MODES::AES_CTR:
	{
		if (mbedtls_aes_crypt_ctr(&_ctx, nBytesIn, &_ncOff, _iv, _strmBlock, 
			pIn, pOut) != 0)
			return CRYPTO_ERROR_CODES::CRYPT_ERROR_MBEDCRYPTO;
	} break;
	}

	// Copy out IV
	if (pIV)
		memcpy(pIV, _iv, N_BLOCK);

	return CRYPTO_ERROR_CODES::CRYPT_OK;
}

// Helper function for self test to reduce code duplication
bool RunTest(CryptoAES* pAES, u8Vec vPlain, u8Vec& vCipher, u8Vec vKey, 
	u8Vec vIV, CRYPTO_MODES nMode, bool bPrintToConsole = false);

bool CryptoAES::SelfTest(bool bPrintToConsole /* = false */)
{
	bool _bSuccess = true;
	CryptoAES _aes;

	// NOTE: Validation vectors pulled from https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers

	// ECB, 128-bit key
	{
		u8Vec _key = 
		{ 0xed, 0xfd,  0xb2, 0x57, 0xcb, 0x37, 0xcd, 0xf1,  
		  0x82, 0xc5,  0x45, 0x5b, 0x0c, 0x0e, 0xfe, 0xbb };
		u8Vec _plain = 
		{ 0x16, 0x95, 0xfe, 0x47, 0x54, 0x21, 0xca, 0xce, 
		  0x35, 0x57, 0xda, 0xca, 0x01, 0xf4, 0x45, 0xff };
		u8Vec _cipher = 
		{ 0x78, 0x88, 0xbe, 0xae, 0x6e, 0x7a, 0x42, 0x63, 
		  0x32, 0xa7, 0xea, 0xa2, 0xf8, 0x08, 0xe6, 0x37 };
		u8Vec _iv = {};

		if (!RunTest(&_aes, _plain, _cipher, _key, _iv, CRYPTO_MODES::AES_ECB, 
			bPrintToConsole))
			_bSuccess = false;
	}

	// ECB, 192-bit key
	{
		u8Vec _key = 
		{ 0x61, 0x39, 0x6c, 0x53, 0x0c, 0xc1, 0x74, 0x9a, 
		  0x5b, 0xab, 0x6f, 0xbc, 0xf9, 0x06, 0xfe, 0x67,
		  0x2d, 0x0c, 0x4a, 0xb2, 0x01, 0xaf, 0x45, 0x54 };
		u8Vec _plain = 
		{ 0x60, 0xbc, 0xdb, 0x94, 0x16, 0xba, 0xc0, 0x8d, 
		  0x7f, 0xd0, 0xd7, 0x80, 0x35, 0x37, 0x40, 0xa5 };
		u8Vec _cipher = 
		{ 0x24, 0xf4, 0x0c, 0x4e, 0xec, 0xd9, 0xc4, 0x98, 
		  0x25, 0x00, 0x0f, 0xcb, 0x49, 0x72, 0x64, 0x7a };
		u8Vec _iv = {};

		if (!RunTest(&_aes, _plain, _cipher, _key, _iv, CRYPTO_MODES::AES_ECB,
			bPrintToConsole))
			_bSuccess = false;
	}

	// ECB, 256-bit key
	{
		u8Vec _key = 
		{ 0xcc, 0x22, 0xda, 0x78, 0x7f, 0x37, 0x57, 0x11, 
		  0xc7, 0x63, 0x02, 0xbe, 0xf0, 0x97, 0x9d, 0x8e, 
		  0xdd, 0xf8, 0x42, 0x82, 0x9c, 0x2b, 0x99, 0xef,
		  0x3d, 0xd0, 0x4e, 0x23, 0xe5, 0x4c, 0xc2, 0x4b };
		u8Vec _plain = 
		{ 0xcc, 0xc6, 0x2c, 0x6b, 0x0a, 0x09, 0xa6, 0x71, 
		  0xd6, 0x44, 0x56, 0x81, 0x8d, 0xb2, 0x9a, 0x4d };
		u8Vec _cipher = 
		{ 0xdf, 0x86, 0x34, 0xca, 0x02, 0xb1, 0x3a, 0x12, 
		  0x5b, 0x78, 0x6e, 0x1d, 0xce, 0x90, 0x65, 0x8b };
		u8Vec _iv = {};

		if (!RunTest(&_aes, _plain, _cipher, _key, _iv, CRYPTO_MODES::AES_ECB, 
			bPrintToConsole))
			_bSuccess = false;
	}

	// CBC, 128-bit key
	{
		u8Vec _key = 
		{ 0x1f, 0x8e, 0x49, 0x73, 0x95, 0x3f, 0x3f, 0xb0, 
		  0xbd, 0x6b, 0x16, 0x66, 0x2e, 0x9a, 0x3c, 0x17 };
		u8Vec _plain = 
		{ 0x45, 0xcf, 0x12, 0x96, 0x4f, 0xc8, 0x24, 0xab, 
		  0x76, 0x61, 0x6a, 0xe2, 0xf4, 0xbf, 0x08, 0x22 };
		u8Vec _cipher = 
		{ 0x0f, 0x61, 0xc4, 0xd4, 0x4c, 0x51, 0x47, 0xc0, 
		  0x3c, 0x19, 0x5a, 0xd7, 0xe2, 0xcc, 0x12, 0xb2 };
		u8Vec _iv = 
		{ 0x2f, 0xe2, 0xb3, 0x33, 0xce, 0xda, 0x8f, 0x98, 
		  0xf4, 0xa9, 0x9b, 0x40, 0xd2, 0xcd, 0x34, 0xa8 };

		if (!RunTest(&_aes, _plain, _cipher, _key, _iv, CRYPTO_MODES::AES_CBC, 
			bPrintToConsole))
			_bSuccess = false;
	}

	// CBC, 192-bit key
	{
		u8Vec _key = 
		{ 0xba, 0x75, 0xf4, 0xd1, 0xd9, 0xd7, 0xcf, 0x7f, 
		  0x55, 0x14, 0x45, 0xd5, 0x6c, 0xc1, 0xa8, 0xab, 
		  0x2a, 0x07, 0x8e, 0x15, 0xe0, 0x49, 0xdc, 0x2c };
		u8Vec _plain = 
		{ 0xc5, 0x1f, 0xc2, 0x76, 0x77, 0x4d, 0xad, 0x94, 
		  0xbc, 0xdc, 0x1d, 0x28, 0x91, 0xec, 0x86, 0x68 };
		u8Vec _cipher = 
		{ 0x70, 0xdd, 0x95, 0xa1, 0x4e, 0xe9, 0x75, 0xe2, 
		  0x39, 0xdf, 0x36, 0xff, 0x4a, 0xee, 0x1d, 0x5d };
		u8Vec _iv = 
		{ 0x53, 0x1c, 0xe7, 0x81, 0x76, 0x40, 0x16, 0x66, 
		  0xaa, 0x30, 0xdb, 0x94, 0xec, 0x4a, 0x30, 0xeb };

		if (!RunTest(&_aes, _plain, _cipher, _key, _iv, CRYPTO_MODES::AES_CBC, 
			bPrintToConsole))
			_bSuccess = false;

	}

	// CBC, 256-bit key
	{
		u8Vec _key = 
		{ 0x6e, 0xd7, 0x6d, 0x2d, 0x97, 0xc6, 0x9f, 0xd1, 
		  0x33, 0x95, 0x89, 0x52, 0x39, 0x31, 0xf2, 0xa6, 
		  0xcf, 0xf5, 0x54, 0xb1, 0x5f, 0x73, 0x8f, 0x21,
		  0xec, 0x72, 0xdd, 0x97, 0xa7, 0x33, 0x09, 0x07 };
		u8Vec _plain = 
		{ 0x62, 0x82, 0xb8, 0xc0, 0x5c, 0x5c, 0x15, 0x30, 
		  0xb9, 0x7d, 0x48, 0x16, 0xca, 0x43, 0x47, 0x62 };
		u8Vec _cipher = 
		{ 0x6a, 0xcc, 0x04, 0x14, 0x2e, 0x10, 0x0a, 0x65, 
		  0xf5, 0x1b, 0x97, 0xad, 0xf5, 0x17, 0x2c, 0x41 };
		u8Vec _iv = 
		{ 0x85, 0x1e, 0x87, 0x64, 0x77, 0x6e, 0x67, 0x96, 
		  0xaa, 0xb7, 0x22, 0xdb, 0xb6, 0x44, 0xac, 0xe8 };

		if (!RunTest(&_aes, _plain, _cipher, _key, _iv, CRYPTO_MODES::AES_CBC, 
			bPrintToConsole))
			_bSuccess = false;
	}

	// CTR, 128-bit key
	{
		u8Vec _key = 
		{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
		  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
		u8Vec _plain = 
		{ 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 
		  0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
		u8Vec _cipher = 
		{ 0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
		  0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce };
		u8Vec _iv = 
		{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		  0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };

		if (!RunTest(&_aes, _plain, _cipher, _key, _iv, CRYPTO_MODES::AES_CTR, 
			bPrintToConsole))
			_bSuccess = false;
	}

	// CTR, 192-bit key
	{
		u8Vec _key = 
		{ 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 
		  0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 
		  0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
		u8Vec _plain = 
		{ 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 
		  0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
		u8Vec _cipher = 
		{ 0x1a, 0xbc, 0x93, 0x24, 0x17, 0x52, 0x1c, 0xa2, 
		  0x4f, 0x2b, 0x04, 0x59, 0xfe, 0x7e, 0x6e, 0x0b };
		u8Vec _iv =
		{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 
		  0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
		
		if (!RunTest(&_aes, _plain, _cipher, _key, _iv, CRYPTO_MODES::AES_CTR, 
			bPrintToConsole))
			_bSuccess = false;
	}

	// CTR, 256-bit key
	{
		u8Vec _key = 
		{ 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 
		  0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 
		  0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 
		  0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
		u8Vec _plain = 
		{ 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 
		  0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
		u8Vec _cipher = 
		{ 0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 
		  0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28 };
		u8Vec _iv = 
		{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 
		  0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
		
		if (!RunTest(&_aes, _plain, _cipher, _key, _iv, CRYPTO_MODES::AES_CTR, 
			bPrintToConsole))
			_bSuccess = false;
	}

	return _bSuccess;
}

// Helper function for self test to reduce code duplication
bool RunTest(CryptoAES* pAES, u8Vec vPlain, u8Vec& vCipher, u8Vec vKey, 
	u8Vec vIV, CRYPTO_MODES nMode, bool bPrintToConsole /* = false */)
{
	bool _bSuccess = true;
	CRYPTO_ERROR_CODES _nRC;
	u8Vec _encrypted, _decrypted;

	std::string _strModeName;
	std::string _strKeySize;
	switch (nMode)
	{
	case CRYPTO_MODES::AES_ECB:
		_strModeName = "AES_ECB ";
		break;
	case CRYPTO_MODES::AES_CBC:
		_strModeName = "AES_CBC ";
		break;
	case CRYPTO_MODES::AES_CTR:
		_strModeName = "AES_CTR ";
		break;
	default:
		_strModeName = "AES_UNKNOWN";
		break;
	}
	_strKeySize = vKey.size() * 8 + "-bit key";

	pAES->Init(nMode);

	// Encryption
	_nRC = pAES->EncryptData(vPlain, _encrypted, vKey, vIV);
	if (CRYPTO_ERROR_CODES::CRYPT_OK != _nRC)
	{
		if (bPrintToConsole)
			std::cout << "CryptoAES SelfTest (" << _strModeName <<  _strKeySize 
			<< ") : FAIL - Encryption returned " << (int)_nRC << std::endl;
		_bSuccess = false;
	}
	if (memcmp(&vCipher[0], &_encrypted[0], _encrypted.size()) != 0)
	{
		if (bPrintToConsole)
			std::cout << "CryptoAES SelfTest (" << _strModeName << _strKeySize
			<< ") : FAIL - Encrypted output does not match expected" 
			<< std::endl;
		_bSuccess = false;
	}

	// Decryption
	_nRC = pAES->DecryptData(vCipher, _decrypted, vKey, vIV);
	if (CRYPTO_ERROR_CODES::CRYPT_OK != _nRC)
	{
		if (bPrintToConsole)
			std::cout << "CryptoAES SelfTest (" << _strModeName << _strKeySize
			<< ") : FAIL - Decryption returned " << (int)_nRC << std::endl;
		_bSuccess = false;
	}
	if (memcmp(&vPlain[0], &_decrypted[0], _decrypted.size()) != 0)
	{
		if (bPrintToConsole)
			std::cout << "CryptoAES SelfTest (" << _strModeName << _strKeySize
			<< ") : FAIL - Decrypted output does not match expected" 
			<< std::endl;
		_bSuccess = false;
	}

	if (_bSuccess && bPrintToConsole)
		std::cout << "CryptoAES SelfTest (" << _strModeName << _strKeySize
		<< ") : PASS" << std::endl << std::endl;

	return _bSuccess;
}
