#include <iostream>
#include "IUserInterface.h"

int main()
{
	ConsoleInterface _interface;

	_interface.Init();
	_interface.RunInterface();
	
	return 0;
}