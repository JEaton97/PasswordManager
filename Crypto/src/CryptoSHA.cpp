#include "ICrypto.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

#define SHA224_LENGTH 28
#define SHA256_LENGTH 32
#define SHA384_LENGTH 48
#define SHA512_LENGTH 64

CRYPTO_ERROR_CODES Hash(HASH_MODES nMode, u8* pData, size_t nDataLength, 
	u8Vec& vHash);

CRYPTO_ERROR_CODES HashSHA::Init(HASH_MODES nMode /* = HASH_MODES::SHA256 */)
{
	switch (m_nMode)
	{
	case HASH_MODES::SHA224:
	case HASH_MODES::SHA256:
	case HASH_MODES::SHA384:
	case HASH_MODES::SHA512:
		break;
	default:
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_BAD_INPUT;
	}
	m_nMode = nMode;
	return CRYPTO_ERROR_CODES::CRYPT_OK;
}

CRYPTO_ERROR_CODES HashSHA::HashData(u8Vec vData, u8Vec& vHash)
{
	return Hash(m_nMode, &vData[0], vData.size(), vHash);
}

CRYPTO_ERROR_CODES HashSHA::HashData(u8* pData, size_t nDataLength, u8Vec& vHash)
{
	return Hash(m_nMode, pData, nDataLength, vHash);
}

uint HashSHA::GetHashLength()
{
	switch (m_nMode)
	{
	case HASH_MODES::SHA224:
		return SHA224_LENGTH;
	case HASH_MODES::SHA256:
		return SHA256_LENGTH;
	case HASH_MODES::SHA384:
		return SHA384_LENGTH;
	case HASH_MODES::SHA512:
		return SHA512_LENGTH;
	default:
		return -1;
	}
}

CRYPTO_ERROR_CODES Hash(HASH_MODES nMode, u8* pData, size_t nDataLength,
	u8Vec& vHash)
{
	switch (nMode)
	{
	case HASH_MODES::SHA224:
	case HASH_MODES::SHA256:
		vHash.resize(nMode == HASH_MODES::SHA224 ?
			SHA224_LENGTH : SHA256_LENGTH);
		if (mbedtls_sha256(pData, nDataLength, &vHash[0],
			nMode == HASH_MODES::SHA224 ? 1 : 0) != 0)
			return CRYPTO_ERROR_CODES::CRYPT_ERROR_MBEDCRYPTO;
		break;
	case HASH_MODES::SHA384:
	case HASH_MODES::SHA512:
		vHash.resize(nMode == HASH_MODES::SHA384 ?
			SHA384_LENGTH : SHA512_LENGTH);
		if (mbedtls_sha512(pData, nDataLength, &vHash[0],
			nMode == HASH_MODES::SHA384 ? 1 : 0) != 0)
			return CRYPTO_ERROR_CODES::CRYPT_ERROR_MBEDCRYPTO;
		break;
	default:
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_BAD_INPUT;
	}
	return CRYPTO_ERROR_CODES::CRYPT_OK;
}