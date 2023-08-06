#include "CryptoKey.h"
#include <iostream>

int main()
{
	uint nNumErrors = 0;
	CRYPTO_ERROR_CODES _nRC;
	CryptoKey _key1, _key2, _key3;
	const char* pTestPassword = "test_password";

	for (uint nTargetSize = 16; nTargetSize <= 32; nTargetSize += 8)
	{
		std::string _strSize = std::to_string((size_t)nTargetSize*8) + " bits";
		// Derive Key
		_nRC = _key1.DeriveNewKey(pTestPassword, nTargetSize);
		if (_nRC != CRYPTO_ERROR_CODES::CRYPT_OK)
		{
			std::cout << "DeriveNewKey (" << _strSize << ") returned " << (uint)_nRC << std::endl;
			nNumErrors++;
		}
		if (_key1.GetKeyValue().size() != nTargetSize)
		{
			std::cout << "Key1 (" << _strSize << ") generated not the correct size" << std::endl;
			nNumErrors++;
		}

		// Write key to file
		_nRC = _key1.WriteKeyToFile("key1_out.txt");
		if (_nRC != CRYPTO_ERROR_CODES::CRYPT_OK)
		{
			std::cout << "WriteKeyToFile (" << _strSize << ") returned " << (uint)_nRC << std::endl;
			nNumErrors++;
		}

		// Read key from file and compare
		_nRC = _key2.ReadKeyFromFile("key1_out.txt");
		if (_nRC != CRYPTO_ERROR_CODES::CRYPT_OK)
		{
			std::cout << "Failed to read key (" << _strSize << ") from file" << std::endl;
			nNumErrors++;
		}
		if (_key2.GetKeyValue().size() != nTargetSize)
		{
			std::cout << "Key read from file (" << _strSize << ") not the correct size" << std::endl;
			nNumErrors++;
		}
		if (memcmp(&_key1.GetKeyValue()[0], &_key2.GetKeyValue()[0],
			_key1.GetKeyValue().size()) != 0)
		{
			std::cout << "Key2 (" << _strSize << ") read from file does not match key1 written"
				<< std::endl;
			nNumErrors++;
		}
		// TODO: Debugging
		_nRC = _key2.WriteKeyToFile("key2_out.txt");
		if (_nRC != CRYPTO_ERROR_CODES::CRYPT_OK)
		{
			std::cout << "WriteKeyToFile (" << _strSize << ") returned " << (uint)_nRC << std::endl;
			nNumErrors++;
		}

		// Re-generate key and compare
		_nRC = _key3.DeriveNewKey(pTestPassword, nTargetSize);
		if (_nRC != CRYPTO_ERROR_CODES::CRYPT_OK)
		{
			std::cout << "DeriveNewKey (" << _strSize << ") returned " << (uint)_nRC << std::endl;
			nNumErrors++;
		}
		if (_key3.GetKeyValue().size() != nTargetSize)
		{
			std::cout << "Key3 (" << _strSize << ") generated not the correct size" << std::endl;
			nNumErrors++;
		}
		if (memcmp(&_key1.GetKeyValue()[0], &_key3.GetKeyValue()[0],
			_key1.GetKeyValue().size()) != 0)
		{
			std::cout << "Key1 (" << _strSize << ") re-generation does not match original" << std::endl;
			nNumErrors++;
		}
	}
	
	if (nNumErrors == 0)
		std::cout << "CryptoKey test: PASS" << std::endl;
	return nNumErrors;
}
