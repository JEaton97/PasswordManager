#include "CryptoKey.h"
#include <iostream>

int main()
{
	CryptoKey _key1, _key2, _key3;
	const char* pTestPassword = "test_password";
	const uint nTargetSize = 16;

	_key1.DeriveNewKey(pTestPassword, nTargetSize);
	if (_key1.GetKeyValue().size() != nTargetSize)
	{
		std::cout << "Key generated not the correct size" << std::endl;
		return 1;
	}

	if (!_key1.WriteKeyToFile("key_out.txt"))
	{
		std::cout << "Failed to write key to file" << std::endl;
		return 2;
	}
	
	if (!_key2.ReadKeyFromFile("key_out.txt"))
	{
		std::cout << "Failed to read key from file" << std::endl;
		return 3;
	}

	if (memcmp(&_key1.GetKeyValue()[0], &_key2.GetKeyValue()[0],
		_key1.GetKeyValue().size()) != 0)
	{
		std::cout << "Key read from file does not match key written"
			<< std::endl;
		return 4;
	}

	_key3.DeriveNewKey(pTestPassword, nTargetSize);
	if (_key3.GetKeyValue().size() != nTargetSize)
	{
		std::cout << "Key generated not the correct size" << std::endl;
		return 5;
	}

	if (memcmp(&_key1.GetKeyValue()[0], &_key3.GetKeyValue()[0],
		_key1.GetKeyValue().size()) != 0)
	{
		std::cout << "Key re-generation does not match original" << std::endl;
		return 6;
	}
	
	std::cout << "CryptoKey test: PASS" << std::endl;
	return 0;
}
