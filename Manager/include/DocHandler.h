#include "ICrypto.h"
#include "CryptoKey.h"
#include <unordered_map>

typedef std::vector<std::string> pass_fields;
typedef std::unordered_map<std::string, pass_fields> pass_map;
typedef std::pair<std::string, pass_fields> pass_entry;

class DocHandler
{

public:
	DocHandler();
	~DocHandler();

	bool CreateDoc(std::string strFileName);
	bool OpenDoc(std::string strFileName);
	bool SaveDoc();

	pass_map* GetData() { return &m_mapData; }

	void SetKeyHandler(CryptoKey* pKeyHandler) { m_pKeyHandler = pKeyHandler; }
	CryptoKey* GetKeyHandler() { return m_pKeyHandler; }

	void SetCrypto(ICrypto* pCrypto) { m_pCrypto = pCrypto; }

private:
	std::string m_strFileName;
	pass_map m_mapData;
	CryptoKey* m_pKeyHandler;
	ICrypto* m_pCrypto;
};