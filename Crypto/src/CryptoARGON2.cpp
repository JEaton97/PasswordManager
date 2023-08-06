#include "ICrypto.h"
#include "argon2.h"

#define SALT_LENGTH 16

bool Hash(HASH_MODES nMode, u8* pData, size_t nDataLength, u8* pHash,
	size_t nHashLength);

CRYPTO_ERROR_CODES HashArgon2::Init(HASH_MODES nMode /* = HASH_MODES::ARGON2ID */)
{
	switch (nMode)
	{
	case HASH_MODES::ARGON2D:
	case HASH_MODES::ARGON2I:
	case HASH_MODES::ARGON2ID:
		m_nMode = nMode;
	default:
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_BAD_INPUT;
	}
	return CRYPTO_ERROR_CODES::CRYPT_OK;
}

CRYPTO_ERROR_CODES HashArgon2::HashData(u8Vec vData, u8Vec& vHash)
{
	vHash.resize(m_nHashLength);

	if (!Hash(m_nMode, &vData[0], vData.size(), &vHash[0], vHash.size()))
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_ARGON2;

	return CRYPTO_ERROR_CODES::CRYPT_OK;
}


CRYPTO_ERROR_CODES HashArgon2::HashData(u8* pData, size_t nDataLength,
	u8Vec& vHash)
{
	vHash.resize(m_nHashLength);

	if (!Hash(m_nMode, pData, nDataLength, &vHash[0], vHash.size()))
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_ARGON2;

	return CRYPTO_ERROR_CODES::CRYPT_OK;
}

bool Hash(HASH_MODES nMode, u8* pData, size_t nDataLength, u8* pHash, 
	size_t nHashLength)
{
	int _nRC;
	uint8_t _pSalt[SALT_LENGTH];
	memset(_pSalt, 0x00, SALT_LENGTH);

	uint32_t _nTCost = 2;			// 2-pass computation
	uint32_t _nMCost = (1 << 16);	// 64 MB memory usage
	uint32_t _nParallelism = 1;		// number of threads and lanes

	switch (nMode)
	{
	case HASH_MODES::ARGON2D:
		_nRC = argon2d_hash_raw(_nTCost, _nMCost, _nParallelism, pData,
			nDataLength, _pSalt, SALT_LENGTH, pHash, nHashLength);
		break;
	case HASH_MODES::ARGON2I:
		_nRC = argon2i_hash_raw(_nTCost, _nMCost, _nParallelism, pData,
			nDataLength, _pSalt, SALT_LENGTH, pHash, nHashLength);
		break;
	case HASH_MODES::ARGON2ID:
		_nRC = argon2id_hash_raw(_nTCost, _nMCost, _nParallelism, pData,
			nDataLength, _pSalt, SALT_LENGTH, pHash, nHashLength);
		break;
	default:
		return false;
	}

	return _nRC == 0;
}