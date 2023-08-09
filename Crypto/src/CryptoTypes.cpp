#include "CryptoTypes.h"

const char* GetCryptoModeStr(CRYPTO_MODES nMode)
{
	switch (nMode)
	{
	case CRYPTO_MODES::AES_ECB: return "AES_ECB";
	case CRYPTO_MODES::AES_CBC: return "AES_CBC";
	case CRYPTO_MODES::AES_CTR: return "AES_CBC";
	case CRYPTO_MODES::TDES_ECB: return "TDES_ECB";
	case CRYPTO_MODES::TDES_CBC: return "TDES_CBC";
	default: return "UNKNOWN";
	}
}

const char* GetHashModeStr(HASH_MODES nMode)
{
	switch (nMode)
	{
	case HASH_MODES::SHA224: return "SHA224";
	case HASH_MODES::SHA256: return "SHA256";
	case HASH_MODES::SHA384: return "SHA384";
	case HASH_MODES::SHA512: return "SHA512";
	case HASH_MODES::ARGON2I: return "ARGON2I";
	case HASH_MODES::ARGON2D: return "ARGON2D";
	case HASH_MODES::ARGON2ID: return "ARGON2ID";
	default: return "UNKNOWN";
	}
}