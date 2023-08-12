#include "IUserInterface.h"
#include "CryptoTypes.h"
#include "DocHandler.h"

#include <iostream>
#include <iomanip>
#ifdef _WIN32
#include <conio.h>
#endif
#ifdef __GNUC__
#include <termios.h>
#include <unistd.h>
#endif


enum class UI_STATE {
	EXITING,
	HOME,
	SETUP,
	MANAGEMENT,
};

UI_STATE g_nState = UI_STATE::HOME;
DocHandler* g_pDocHandler;
CryptoAES g_AES;
CryptoTDES g_TDES;

#define DIVIDER_STR \
"\n--------------------------------------------------------------------------\n"

// Get first character input from user with input hidden in console
int GetInputSingle();
// Get string input from user with input displayed in console
std::string GetInputString();
// Get string input from user with input hidden in console
std::string GetInputStringHidden();
// Prompt user for password fields (service, username, password, etc)
pass_fields InputPasswordFields();
// Prompt user for cipher mode to use
CRYPTO_MODES SelectCryptoMode();
// Display formatted password table
void DisplayPasswordTable(pass_map* pMap);




ConsoleInterface::~ConsoleInterface()
{
	if (g_pDocHandler)
		delete g_pDocHandler;
}

bool ConsoleInterface::Init()
{
	return true;
}

bool ConsoleInterface::RunInterface()
{
	while (g_nState != UI_STATE::EXITING)
	{
		switch (g_nState)
		{
		case UI_STATE::HOME:
			RunHomeMenu();
			break;
		case UI_STATE::SETUP:
			RunSetupMenu();
			break;
		case UI_STATE::MANAGEMENT:
			RunManagementMenu();
			break;
		default:
			// Unknown state, abort
			std::cout << "\nInternal Error Occurred. Exiting...\n";
			return false;
		}
	}
	return true;
}

void ConsoleInterface::RunHomeMenu()
{

	std::cout << DIVIDER_STR;
	std::cout << "    PASSWORD MANAGER - HOME\n\n";
	std::cout << " 0 - Perform Setup\n";
	std::cout << " x - Exit Application\n";
	std::cout << DIVIDER_STR;

	while (true)
	{
		int _nInput = GetInputSingle();
		switch (_nInput)
		{
		case '0':
			g_nState = UI_STATE::SETUP;
			return;
		case 'x':
			g_nState = UI_STATE::EXITING;
			return;
		}
	}
}

void ConsoleInterface::RunSetupMenu()
{
	bool _bShowMenu = true;
	bool _bKeyGenerated = false;
	CRYPTO_MODES _nMode = CRYPTO_MODES::AES_CBC;
	std::string _strKeyFile;
	std::string _strDocFile;
	std::string _strPassword;

	if (g_pDocHandler)
		delete g_pDocHandler;
	g_pDocHandler = new DocHandler();

	while (_bShowMenu)
	{
		std::cout << DIVIDER_STR;
		std::cout << "    PASSWORD MANAGER - SETUP\n\n";
		std::cout << " Crypto Mode       : " << GetCryptoModeStr(_nMode) 
			<< "\n";
		std::cout << " Key Selected      : " << (_bKeyGenerated ? "Generated" 
			: _strKeyFile) << "\n";
		std::cout << " Document Selected : " << _strDocFile << "\n\n";

		std::cout << " 0 - Select Crypto Mode\n";
		std::cout << " 1 - Read Key From File\n";
		std::cout << " 2 - Generate Key From Password\n";
		std::cout << " 3 - Select Password Document\n";
		std::cout << " 4 - Generate New Password Document\n\n";

		std::cout << " f - Finish Setup\n";
		std::cout << " h - Return to Home Page\n";
		std::cout << " x - Exit Application\n";
		std::cout << DIVIDER_STR;

	
		int _nInput = GetInputSingle();
		switch (_nInput)
		{
		case '0':	// Select Crypto Mode
			_nMode = SelectCryptoMode();
			break;
		case '1':	// Read Key From File
			std::cout << "Enter full or relative path to key file:\n";
			_strKeyFile = GetInputString();
			_bKeyGenerated = false;
			break;
		case '2':	// Generate New Key
			std::cout << "Enter password used to generate key:\n";
			_strPassword = GetInputStringHidden();
			_bKeyGenerated = true;
			break;
		case '3':	// Select Password Document
			std::cout << "Enter full or relative path to password document:\n";
			_strDocFile = GetInputString();
			break;
		case '4':	// Generate New Password Document
			std::cout << "Enter full or relative path to save the document:\n";
			_strDocFile = GetInputString();
			if (!g_pDocHandler->CreateDoc(_strDocFile))
			{
				std::cout << "Failed to create document or found existing document with the name provided\n";
				_strDocFile.clear();
			}
			break;
		case 'f':
			if (!_bKeyGenerated && _strKeyFile.size() == 0)
			{
				std::cout << "Please select or generate a key before finalizing\n";
				break;
			}
			if (_strDocFile.size() == 0)
			{
				std::cout << "Please select or generate a password document before finalizing\n";
				break;
			}
			g_nState = UI_STATE::MANAGEMENT;
			_bShowMenu = false;
			break;
		case 'h':
			g_nState = UI_STATE::HOME;
			_bShowMenu = false;
			break;
		case 'x':
			g_nState = UI_STATE::EXITING;
			_bShowMenu = false;
			break;
		}
	}

	if (g_nState == UI_STATE::MANAGEMENT)
	{
		// Initialize Cipher Class
		int _nKeySize = 0;
		switch (_nMode)
		{
		case CRYPTO_MODES::AES_ECB:
		case CRYPTO_MODES::AES_CBC:
		case CRYPTO_MODES::AES_CTR:
		{
			_nKeySize = 32;	// If generating key, use 256-bit key
			g_AES.Init(_nMode);
			g_pDocHandler->SetCrypto(&g_AES);
		} break;
			// TDES Mode Types
		case CRYPTO_MODES::TDES_ECB:
		case CRYPTO_MODES::TDES_CBC:
		{
			_nKeySize = 24;	// If generating key, use 192-bit key (3-key)
			g_TDES.Init(_nMode);
			g_pDocHandler->SetCrypto(&g_TDES);
		} break;
		}
		// Initialize Key
		if (_bKeyGenerated)
		{
			if (g_pDocHandler->GetKeyHandler()->DeriveNewKey(_strPassword,
				_nKeySize) != CRYPTO_ERROR_CODES::CRYPT_OK)
			{
				std::cout << "Failed to generate key\n";
				g_nState = UI_STATE::SETUP;
			}
		}
		else
		{
			if (g_pDocHandler->GetKeyHandler()->ReadKeyFromFile(_strKeyFile)
				!= CRYPTO_ERROR_CODES::CRYPT_OK)
			{
				std::cout << "Failed to read key from file\n";
				g_nState = UI_STATE::SETUP;
			}
		}
		// Load document
		if (!g_pDocHandler->OpenDoc(_strDocFile))
		{
			std::cout << "Failed to load password document\n";
			g_nState = UI_STATE::SETUP;
		}
	}

	// Clear any sensitive data from memory
	if (_strKeyFile.size() > 0)
		_strKeyFile = std::string(_strKeyFile.size(), '\0');
	if (_strDocFile.size() > 0)
		_strDocFile = std::string(_strDocFile.size(), '\0');
	if (_strPassword.size() > 0)
		_strPassword = std::string(_strPassword.size(), '\0');

	return;
}

void ConsoleInterface::RunManagementMenu()
{
	bool _bShowMenu = true;
	pass_map* _pMap = g_pDocHandler->GetData();
	while (_bShowMenu)
	{
		std::cout << DIVIDER_STR;
		std::cout << "    PASSWORD MANAGER - MANAGEMENT\n\n";

		DisplayPasswordTable(_pMap);

		std::cout << " 0 - Add New Entry\n";
		std::cout << " 1 - Delete Entry\n";
		std::cout << " 2 - Save Changes\n";

		std::cout << " h - Return to Home Page\n";
		std::cout << " x - Exit Application\n";
		std::cout << DIVIDER_STR;

		int _nInput = GetInputSingle();
		switch (_nInput)
		{
		case '0':	// Add Entry
		{
			std::cout << "Enter name of entry to add:\n";
			std::string _strTmp = GetInputString();
			if (_pMap->find(_strTmp) != _pMap->end())
				std::cout << _strTmp << " already exists\n";
			else
				_pMap->insert(pass_entry(_strTmp, InputPasswordFields()));
		} break;
		case '1':	// Delete Entry
		{
			std::cout << "Enter name of entry to delete:\n";
			std::string _strTmp = GetInputString();
			if (_pMap->find(_strTmp) != _pMap->end())
				_pMap->erase(_strTmp);
			else
				std::cout << _strTmp << " not found\n";
		} break;
		case '2':	// Save Changes
		{
			g_pDocHandler->SaveDoc();
			std::cout << "Changes saved to file\n";
		} break;
		case 'h':
		{
			g_nState = UI_STATE::HOME;
			_bShowMenu = false;
		} break;
		case 'x':
		{
			g_nState = UI_STATE::EXITING;
			_bShowMenu = false;
		} break;
		}
	}
}


int GetInputSingle()
{
	int _ch;
#ifdef _WIN32
	_ch = _getch();
#endif
#ifdef __GNUC__
	struct termios oldt, newt;
	tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;
	newt.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);
	_ch = getchar();
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
	return _ch;
}

std::string GetInputString()
{
	std::string _str;
	int _ch = GetInputSingle();
	while (_ch != '\n' && _ch != '\r')
	{
		if (_ch == 8 || _ch == 127)	// Backspace, delete
		{
			if (_str.size() > 0)
			{
				_str.pop_back();
				std::cout << '\b' << ' ' << '\b';
				std::cout.flush();
			}
		}
		else
		{
			_str.append(1, (char)_ch);
			std::cout << (char)_ch;
			std::cout.flush();
		}
		_ch = GetInputSingle();
	}
	std::cout << '\n';
	return _str;
}

std::string GetInputStringHidden()
{
	std::string _str;
	int _ch = GetInputSingle();
	while (_ch != '\n' && _ch != '\r')
	{
		if (_ch == 8 || _ch == 127)	// Backspace, delete
		{
			if (_str.size() > 0)
				_str.pop_back();
		}
		else
		{
			_str.append(1, (char)_ch);
		}
		_ch = GetInputSingle();
	}
	std::cout << '\n';
	return _str;
}

pass_fields InputPasswordFields()
{
	pass_fields _fields;
	std::cout << "Enter field:\n";
	_fields.push_back(GetInputString());
	std::cout << "Add more fields? <y/N>\n";
	int _nInput = GetInputSingle();
	while (_nInput == 'y' || _nInput == 'Y')
	{
		std::cout << "Enter field:\n";
		_fields.push_back(GetInputString());

		std::cout << "Add more fields? <y/N>\n";
		_nInput = GetInputSingle();
	}
	return _fields;
}

CRYPTO_MODES SelectCryptoMode()
{
	int _nInput;
	bool _bValid = false;
	std::cout << " Select Crypto Mode:\n";
	for (int i = (int)CRYPTO_MODES::BEGIN + 1; i < (int)CRYPTO_MODES::LAST; i++)
	{
		std::cout << i << " - " << GetCryptoModeStr((CRYPTO_MODES)i) << "\n";
	}

	while (!_bValid)
	{
		_nInput = GetInputSingle() - 48;	// Convert from char value to integer
		if (_nInput > (int)CRYPTO_MODES::BEGIN &&
			_nInput < (int)CRYPTO_MODES::LAST)
			_bValid = true;
	}
	return (CRYPTO_MODES)_nInput;
}

void DisplayPasswordTable(pass_map* pMap)
{
	// Determine entry sizes for table formatting
	std::vector<size_t> _vMaxSizes;
	size_t _nMaxFields = 0;
	for (pass_map::iterator it = pMap->begin(); it != pMap->end(); it++)
	{
		size_t _nIndx = 0;
		if (_vMaxSizes.size() < _nIndx + 1)
			_vMaxSizes.push_back(it->first.size());
		else if (_vMaxSizes[_nIndx] < it->first.size())
			_vMaxSizes[_nIndx] = it->first.size();
		_nIndx++;
		for (pass_fields::iterator it2 = it->second.begin(); it2 != it->second.end(); it2++)
		{
			if (_vMaxSizes.size() < _nIndx + 1)
				_vMaxSizes.push_back(it2->size());
			else if (_vMaxSizes[_nIndx] < it2->size())
				_vMaxSizes[_nIndx] = it2->size();
			_nIndx++;
			if (_nIndx > _nMaxFields)
				_nMaxFields = _nIndx;
		}
	}

	// Print map to stdout
	for (pass_map::iterator it = pMap->begin(); it != pMap->end(); it++)
	{
		int _nFieldIndx = 0;
		std::cout << " | ";
		std::cout << std::setw(_vMaxSizes[_nFieldIndx++]) << std::left;
		std::cout << it->first << " | ";
		//for (pass_fields::iterator it2 = it->second.begin(); it2 != it->second.end(); it2++)
		for (int i = 0; i < _nMaxFields - 1; i++)
		{
			std::cout << std::setw(_vMaxSizes[_nFieldIndx++]) << std::left;
			if (it->second.size() >= (size_t)i + 1)
				std::cout << it->second[i] << " | ";
			else
				std::cout << std::string() << " | ";
		}
		std::cout << "\n";
	}
	std::cout << "\n";
}