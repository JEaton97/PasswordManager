#include "CryptoKey.h"
#include "ICrypto.h"
#include <fstream>

#define MIN_KEY_LENGTH 16

CryptoKey::~CryptoKey()
{
	if (m_vValue.size() == 0)
		return;
	// Zeroize memory
	memset(&m_vValue[0], 0, m_vValue.size());
}

CRYPTO_ERROR_CODES CryptoKey::ReadKeyFromFile(std::string strFileName)
{
	// Prepare SHA256 hash
	HashSHA _sha;
	u8Vec _vHash, _vCalcHash;
	size_t _nHashLength = _sha.GetHashLength();

	// Open file requested
	std::ifstream _fileIn(strFileName.c_str(), std::ios::in | std::ios::binary);
	if (!_fileIn.is_open())
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_FILE_IO;

	// Check file size
	size_t _nFileSize;
	_fileIn.seekg(0, _fileIn.end);
	_nFileSize = _fileIn.tellg();
	_fileIn.seekg(0, _fileIn.beg);
	switch ((_nFileSize - _nHashLength) * 8)
	{
	case 128:
	case 192:
	case 256:
		break;
	default:
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_FILE_SIZE;
	}

	// Read data
	_vHash.resize(_nHashLength);
	_fileIn.read((char*)&_vHash[0], _nHashLength);
	m_vValue.resize(_nFileSize - _nHashLength);
	_fileIn.read((char*)&m_vValue[0], _nFileSize - _nHashLength);

	// Calculate hash and compare
	CRYPTO_ERROR_CODES _nRC = _sha.HashData(m_vValue, _vCalcHash);
	if (_nRC != CRYPTO_ERROR_CODES::CRYPT_OK)
		return _nRC;
	if (memcmp(&_vHash[0], &_vCalcHash[0], _nHashLength) != 0)
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_FILE_CORRUPTED;

	_fileIn.close();

	return CRYPTO_ERROR_CODES::CRYPT_OK;
}

CRYPTO_ERROR_CODES CryptoKey::WriteKeyToFile(std::string strFileName)
{
	// Calculate SHA256 hash
	HashSHA _sha;
	u8Vec _vHash;
	size_t _nHashLength = _sha.GetHashLength();
	CRYPTO_ERROR_CODES _nRC = _sha.HashData(m_vValue, _vHash);
	if (_nRC != CRYPTO_ERROR_CODES::CRYPT_OK)
		return _nRC;

	// Open file requested
	std::ofstream _fileOut(strFileName.c_str(), std::ios::out | 
		std::ios::binary);
	if (!_fileOut.is_open())
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_FILE_IO;

	// Write data
	_fileOut.write((char*)&_vHash[0], _nHashLength);
	_fileOut.write((char*)&m_vValue[0], m_vValue.size());

	_fileOut.flush();
	_fileOut.close();

	return CRYPTO_ERROR_CODES::CRYPT_OK;
}

CRYPTO_ERROR_CODES CryptoKey::DeriveNewKey(std::string strPassword, 
	uint nTargetSize)
{
	// Check for valid key size
	switch (nTargetSize * 8)
	{
	case 128:
	case 192:
	case 256:
		break;
	default:
		return CRYPTO_ERROR_CODES::CRYPT_ERROR_BAD_INPUT;
	}

	// Use argon2id password hashing to derive new key
	HashArgon2 _argon2;
	_argon2.SetHashLength(nTargetSize);
	return _argon2.HashData((u8*)strPassword.c_str(), strPassword.size(), 
		m_vValue);
}
