#ifndef _CRYPTO_KEY
#define _CRYPTO_KEY

#include <string>
#include <vector>
#include "CryptoTypes.h"

class CryptoKey {

public:
	CryptoKey() {}
	~CryptoKey();

	// Read from file
	bool ReadKeyFromFile(std::string strFileName);
	// Write to file
	bool WriteKeyToFile(std::string strFileName);
	// Derive new pseudorandom key
	bool DeriveNewKey(std::string strPassword, uint nTargetSize);

	// Get Key Value
	std::vector<u8> GetKeyValue() { return m_vValue; }

private:
	std::vector<u8> m_vValue;
};

#endif // _CRYPTO_KEY