#include "DocHandler.h"
#include <fstream>
#include <sstream>

/*

Data saved in the following format:
HASH[CRYPTO[CONTENTS]]
HASH[CONTENTS]
CRYPTO [CONTENTS]

Where CONTENTS = [
	int numMapKeys
	int key0Size, str key0, int numEntries, int data0Size, str data0, ... int dataNSize, str dataN
	...
	int keyNSize, str keyN, int numEntries, int data0Size, str data0, ... int dataNSize, str dataN
]


*/

DocHandler::DocHandler()
{
	m_pCrypto = nullptr;
	m_pKeyHandler = new CryptoKey();
}

DocHandler::~DocHandler()
{
	// Clear any sensitive data from memory
	for (pass_map::iterator entry = m_mapData.begin(); entry != m_mapData.end(); entry++)
	{
		for (pass_fields::iterator data = entry->second.begin(); data != entry->second.end(); data++)
		{
			*data = std::string(data->size(), '\0');
		}
	}
}

bool DocHandler::CreateDoc(std::string strFileName)
{
	std::ifstream _fileIn(strFileName.c_str(), std::ios::in | std::ios::binary);
	if (_fileIn.is_open())
	{
		// File already exists
		_fileIn.close();
		return false;
	}

	std::ofstream _fileOut(strFileName.c_str(), std::ios::out | std::ios::binary);
	if (!_fileOut.is_open())
		return false;
	_fileOut.close();
	m_strFileName = strFileName;
	return true;
}


bool DocHandler::OpenDoc(std::string strFileName)
{
	std::ifstream _fileIn(strFileName.c_str(), std::ios::in | std::ios::binary);
	if (!_fileIn.is_open())
	{
		// Failed to establish file handle
		//std::cout << "OpenDoc: Failed to establish file handle!\n";
		return false;
	}
	m_strFileName = strFileName;

	// Check file size
	size_t _nFileSize;
	_fileIn.seekg(0, _fileIn.end);
	_nFileSize = _fileIn.tellg();
	_fileIn.seekg(0, _fileIn.beg);

	// If empty file, return
	if (_nFileSize == 0)
		return true;

	HashSHA _sha;
	u8Vec _vHashPlain, _vHashCipher, _vCalcHash, _vIV;
	_vHashPlain.resize(_sha.GetHashLength());
	_vHashCipher.resize(_sha.GetHashLength());

	// Make sure file is appropriate size
	if (_nFileSize < (_sha.GetHashLength() * (size_t)2) + m_pCrypto->GetBlockSize())
		return false;

	// Check hash
	_fileIn.read((char*)&_vHashCipher[0], _vHashCipher.size());
	_fileIn.read((char*)&_vHashPlain[0], _vHashPlain.size());

	u8Vec _vCipher, _vPlain;
	_vCipher.resize(_nFileSize - ((size_t)_sha.GetHashLength() * 2));
	_fileIn.read((char*)&_vCipher[0], _vCipher.size());
	_fileIn.close();

	_sha.HashData(_vCipher, _vCalcHash);
	if (memcmp(&_vHashCipher[0], &_vCalcHash[0], _vHashCipher.size()) != 0)
	{
		//std::cout << "OpenDoc: Calc hash (cipher) does not match saved hash!\n";
		return false;
	}

	m_pCrypto->DecryptData(_vCipher, _vPlain, m_pKeyHandler->GetKeyValue(), _vIV);
	_sha.HashData(_vPlain, _vCalcHash);
	if (memcmp(&_vHashPlain[0], &_vCalcHash[0], _vHashPlain.size()) != 0)
	{
		//std::cout << "OpenDoc: Calc hash (plain) does not match saved hash!\n";
		return false;
	}

	size_t _nMapSize = 0;
	size_t _nFieldSize = 0;
	size_t _nIndx = 0;
	size_t* _nTmp;

	// Read number of entries
	_nTmp = (size_t*)&_vPlain[_nIndx];
	_nIndx += sizeof(size_t);
	_nMapSize = *_nTmp;
	m_mapData.reserve(_nMapSize);
	for (int i = 0; i < _nMapSize; i++)
	{
		pass_entry _entry;
		
		// Read key size
		_nTmp = (size_t*)&_vPlain[_nIndx];
		_nIndx += sizeof(size_t);
		// Read key
		_entry.first.append((char*)&_vPlain[_nIndx], *_nTmp);
		_nIndx += *_nTmp;

		// Read num entries
		_nTmp = (size_t*)&_vPlain[_nIndx];
		_nIndx += sizeof(size_t);
		_nFieldSize = *_nTmp;
		_entry.second.reserve(_nFieldSize);
		for (int j = 0; j < _nFieldSize; j++)
		{
			// Read entry size
			_nTmp = (size_t*)&_vPlain[_nIndx];
			_nIndx += sizeof(size_t);
			// Read entry
			_entry.second.push_back(std::string((char*)&_vPlain[_nIndx], *_nTmp));
			_nIndx += *_nTmp;
		}
		
		m_mapData.insert(_entry);
	}

	// Clear any sensitive data
	memset(&_vPlain[0], 0, _vPlain.size());
	
	return true;
}


bool DocHandler::SaveDoc()
{
	// If data is empty return
	if (m_mapData.size() == 0)
		return true;

	std::ofstream _fileOut(m_strFileName.c_str(), std::ios::out | std::ios::binary);
	if (!_fileOut.is_open())
	{
		// Failed to establish file handle
		//std::cout << "SaveDoc: Failed to establish file handle!\n";
		return false;
	}

	HashSHA _sha;
	u8Vec _vPlain, _vCipher, _vIV, _vHashPlain, _vHashCipher;
	

	// Calculate size and add padding
	size_t _nTargetSize = sizeof(size_t);		// size of map
	for (pass_map::iterator entries = m_mapData.begin(); entries != m_mapData.end(); entries++)
	{
		_nTargetSize += sizeof(size_t);			// size of key
		_nTargetSize += entries->first.size();	// key value
		_nTargetSize += sizeof(size_t);			// number entries
		for (pass_fields::iterator data = entries->second.begin(); data != entries->second.end(); data++)
		{
			_nTargetSize += sizeof(size_t);		// size of data
			_nTargetSize += data->size();		// data value
		}
	}
	if (_nTargetSize % m_pCrypto->GetBlockSize() != 0)
	_nTargetSize += m_pCrypto->GetBlockSize() - (_nTargetSize % m_pCrypto->GetBlockSize());


	// Populate buffer for encryption
	size_t _nTmp, _nIndx = 0;
	_vPlain.resize(_nTargetSize);
	
	_nTmp = m_mapData.size();
	memcpy(&_vPlain[_nIndx], &_nTmp, sizeof(size_t));
	_nIndx += sizeof(size_t);
	for (pass_map::iterator entries = m_mapData.begin(); entries != m_mapData.end(); entries++)
	{
		// Key size
		_nTmp = entries->first.size();
		memcpy(&_vPlain[_nIndx], &_nTmp, sizeof(size_t));
		_nIndx += sizeof(size_t);
		// Key value
		memcpy(&_vPlain[_nIndx], entries->first.c_str(), entries->first.size());
		_nIndx += entries->first.size();
		// Num Entries
		_nTmp = entries->second.size();
		memcpy(&_vPlain[_nIndx], &_nTmp, sizeof(size_t));
		_nIndx += sizeof(size_t);

		for (pass_fields::iterator data = entries->second.begin(); data != entries->second.end(); data++)
		{
			// Data size
			_nTmp = data->size();
			memcpy(&_vPlain[_nIndx], &_nTmp, sizeof(size_t));
			_nIndx += sizeof(size_t);
			// Data value
			memcpy(&_vPlain[_nIndx], data->c_str(), data->size());
			_nIndx += data->size();
		}
	}

	// Encrypt and compute hashes
	m_pCrypto->EncryptData(_vPlain, _vCipher, m_pKeyHandler->GetKeyValue(), _vIV);

	
	_sha.HashData(_vPlain, _vHashPlain);
	_sha.HashData(_vCipher, _vHashCipher);

	_fileOut.write((char*)&_vHashCipher[0], _vHashCipher.size());
	_fileOut.write((char*)&_vHashPlain[0], _vHashPlain.size());
	_fileOut.write((char*)&_vCipher[0], _vCipher.size());
	_fileOut.flush();
	_fileOut.close();

	// Clear any sensitive data
	memset(&_vPlain[0], 0, _vPlain.size());

	return true;
}