#include <iostream>

#include "ICrypto.h"

int main()
{
	bool bSuccess = CryptoTDES::SelfTest(true);
	if (bSuccess)
		std::cout << "*** CryptoTDES self test: PASS" << std::endl;
	else
		std::cout << "*** CryptoTDES self test: FAIL" << std::endl;
	
	return bSuccess;
}