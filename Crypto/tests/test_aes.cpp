#include <iostream>

#include "ICrypto.h"

int main()
{
	bool bSuccess = CryptoAES::SelfTest(true);
	if (bSuccess)
		std::cout << "*** CryptoAES self test: PASS" << std::endl;
	else
		std::cout << "*** CryptoAES self test: FAIL" << std::endl;
	
	return bSuccess;
}