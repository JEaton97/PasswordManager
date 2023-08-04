#include "CryptoKey.h"
#include "argon2.h"
#include <fstream>

#define SALT_LENGTH 16

CryptoKey::~CryptoKey()
{
	if (m_vValue.size() == 0)
		return;
	// Zeroize memory
	for (u8Vec::iterator it = m_vValue.begin(); it != m_vValue.end(); it++)
	{
		*it = 0;
	}
}

bool CryptoKey::ReadKeyFromFile(std::string strFileName)
{
	// Open file requested
	std::ifstream _fileIn(strFileName.c_str(), std::ios::in | std::ios::binary);
	if (!_fileIn.is_open())
		return false;

	// Check file size
	size_t _nFileSize;
	_fileIn.seekg(0, _fileIn.end);
	_nFileSize = _fileIn.tellg();
	_fileIn.seekg(0, _fileIn.beg);

	// Read data
	m_vValue.resize(_nFileSize);
	for (int i = 0; i < _nFileSize; i++)
		_fileIn >> m_vValue[i];

	_fileIn.close();

	return true;
}

bool CryptoKey::WriteKeyToFile(std::string strFileName)
{
	// Open file requested
	std::ofstream _fileOut(strFileName.c_str(), std::ios::out | std::ios::binary);
	if (!_fileOut.is_open())
		return false;

	// Write data
	for (int i = 0; i < m_vValue.size(); i++)
		_fileOut << m_vValue[i];

	_fileOut.flush();
	_fileOut.close();

	return true;
}

bool CryptoKey::DeriveNewKey(std::string strPassword, uint nTargetSize)
{
	int _nRC;
	uint8_t _pSalt[SALT_LENGTH];
	memset(_pSalt, 0x00, SALT_LENGTH);

	u8* _pPass = (u8*)strPassword.c_str();
	size_t _nPassLength = strPassword.size();

	uint32_t _nTCost = 2;			// 2-pass computation
	uint32_t _nMCost = (1 << 16);	// 64 MB memory usage
	uint32_t _nParallelism = 1;		// number of threads and lanes

	m_vValue.resize(nTargetSize);

	_nRC = argon2id_hash_raw(_nTCost, _nMCost, _nParallelism, _pPass, 
		_nPassLength, _pSalt, SALT_LENGTH, &m_vValue[0], nTargetSize);

	return _nRC == ARGON2_OK;
}

