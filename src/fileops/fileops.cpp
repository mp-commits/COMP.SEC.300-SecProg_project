/**
 * @file cryptfile.cpp
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-03-23
 * 
 * @copyright Copyright (c) 2023
 * 
 */

// Common includes
#include "project_definitions.hpp"
#include "stringvector.hpp"

// Library public includes
#include "csv/csv_file.hpp"
#include "cryptfile/cryptfile.hpp"

// Private includes
#include "encryption/sha256.hpp"
#include "encryption/util.hpp"
#include "services/idservice.hpp"
#include "boost/tokenizer.hpp"

// STL includes
#include <iostream>
#include <sstream>
#include <map>

#define OUTPUT_HEADER "\"url\",\"username\",\"password\""
#define OUTPUT_SEPARATOR ','

using namespace std;
using namespace fileops;
using namespace passwords;
using namespace encryption;
using namespace encryptionUtil;

typedef std::map<std::string, size_t> KeyMap_t;

static inline size_t Max3(size_t a, size_t b, size_t c)
{
    size_t temp = (a > b) ? a : b;
    return (temp > c) ? temp : c;
}

static inline void Escape(string& s)
{
    s.insert(s.begin(), '"');
    s.insert(s.end(), '"');
}

static StringVector_t Tokenize(const string& line)
{
    boost::tokenizer<boost::escaped_list_separator<char> > tok(line);
    StringVector_t tokens;

    for(boost::tokenizer<boost::escaped_list_separator<char>>::iterator beg = tok.begin(); beg != tok.end(); ++beg)
    {
        tokens.push_back(*beg);
    }

    return tokens;
}

static KeyMap_t GenerateKeys(const StringVector_t& tokens)
{
    KeyMap_t keys;

    for (size_t i = 0; i < tokens.size(); i++)
    {
        string key = tokens[i];

        // Transform to lowercase just in case
        transform(key.begin(), key.end(), key.begin(), [](unsigned char c){ return std::tolower(c); });
        keys.insert({key, i});
    }

    return keys;
}

static bool KeyExists(const KeyMap_t& map, string key)
{
    if (map.find(key) != map.end())
    {
        return true;
    }
    return false;
}

string LoginToCsvLine(Login_t login)
{
    Escape(login.url);
    Escape(login.username);
    Escape(login.password);

    stringstream ss;
    ss << login.url << OUTPUT_SEPARATOR << login.username << OUTPUT_SEPARATOR << login.password << endl;
    return ss.str();
}

Login_t CsvLineToLogin(const string& str, KeyMap_t keys = {})
{
    Login_t login;
    auto t = Tokenize(str);

    if (keys.empty())
    {
        if (t.size() == 3U)
        {
            login.url = t[0];
            login.username = t[1];
            login.password = t[2];
        }
        else
        {
            throw std::runtime_error(ERR_STR_ARG);
        }
    }
    else
    {
        const size_t idxUrl = keys[KEY_STR_URL], idxUsername = keys[KEY_STR_USERNAME], idxPassword = keys[KEY_STR_PASSWORD];
        const size_t maxIdx = Max3(idxUrl, idxPassword, idxUsername);
        
        if (t.size() > maxIdx)
        {
            login.username = t[idxUsername];
            login.url = t[idxUrl];
            login.password = t[idxPassword];
        }
        else
        {
            throw std::runtime_error("Ignored invalid line in the file");
        }
    }

    return login;
}

CryptFile::CryptFile(const string& password) : m_password(password)
{

}

CryptFile::~CryptFile()
{

}

bool CryptFile::Load(ifstream& file, vector<passwords::Login_t>& logins)
{
    file.seekg(0, ios_base::end);
    size_t fileSize = file.tellg();
    file.seekg(0, ios_base::beg);

    if (fileSize <= PROJECT_SALT_SIZE + PROJECT_ID_HEADER_SIZE)
    {
        throw runtime_error(ERR_STR_FILE);
        return false;
    }
    
    const size_t cryptDataLength = fileSize - (PROJECT_SALT_SIZE + PROJECT_ID_HEADER_SIZE);

    ByteVector_t header(PROJECT_ID_HEADER_SIZE);
    ByteVector_t salt(PROJECT_SALT_SIZE);
    ByteVector_t cryptData(cryptDataLength);
    ByteVector_t plainData;

    file.read((char*)header.data(), PROJECT_ID_HEADER_SIZE);

    if (!IDSERVICE_IsApplicationHeader(header))
    {
        throw runtime_error(ERROR_STR_INCOMPATIBLE_FILE);
    }

    file.read((char*)salt.data(), PROJECT_SALT_SIZE);
    file.read((char*)cryptData.data(), cryptDataLength);

    IDSERVICE_AddId(salt);

    ENCRYPTION_Key256_t key;
    EVPKDF kdf(m_password, salt);
    kdf.derive256(key);

    AESGCM aes(key);

    if (!aes.decrypt(cryptData, plainData))
    {
        throw runtime_error(ERR_STR_DECRYPT);
    }
    if (!VerifyChecksum(plainData))
    {
        throw runtime_error(ERR_STR_CHECKSUM);
    }
    
    stringstream ss;
    ss << vectorToString(plainData);

    string loginStr;
    while (getline(ss, loginStr))
    {
        try
        {
            logins.push_back(CsvLineToLogin(loginStr));
        }
        catch(...)
        {
            continue;
        }

    }

    return true;
}

bool CryptFile::Save(ofstream& file, const vector<passwords::Login_t>& logins)
{
    if (!logins.empty())
    {
        file.seekp(ios_base::beg);
        
        stringstream ss;

        for (auto& login: logins)
        {
            ss << LoginToCsvLine(login);
        }

        ByteVector_t plainData = StringToVector(ss.str());
        WriteChecksum(plainData);

        ByteVector_t salt(PROJECT_SALT_SIZE);
        GenerateRandom(salt.data(), PROJECT_SALT_SIZE);

        IDSERVICE_AddId(salt);

        EVPKDF kdf(m_password, salt);

        ENCRYPTION_Key256_t key;
        kdf.derive256(key);

        AESGCM aes(key);

        ByteVector_t cryptData;
        aes.encrypt(plainData, cryptData);

        for (auto c: IDSERVICE_GetApplicationHeader())
        {
            file.put(c);
        }

        for (auto c: salt)
        {
            file.put(c);
        }

        for (auto c: cryptData)
        {
            file.put(c);
        }

        return file.good();
    }

    return false;
}

bool CryptFile::VerifyChecksum(ByteVector_t& data)
{
    bool result = false;

    if (data.size() > SHA256_SIZE)
    {
        ByteVector_t expected(data.end() - SHA256_SIZE, data.end());

        data.erase(data.end() - SHA256_SIZE, data.end());

        ByteVector_t actual = CalculateSHA256(data);
        return actual == expected;
    }

    return result;
}

void CryptFile::WriteChecksum(ByteVector_t& data)
{
    if (!data.empty())
    {
        ByteVector_t sha256 = CalculateSHA256(data);
    
        assert(sha256.size() == SHA256_SIZE);

        for (auto c: sha256)
        {
            data.push_back(c);
        }
    }
}

bool csv::CSV_GetLoginsFromFile(ifstream& file, vector<passwords::Login_t>& logins)
{
    string line;
    KeyMap_t keys;
    bool firstLine = true;
    bool success = false;

    while (getline(file, line))
    {
        try
        {
            const StringVector_t tokens = Tokenize(line);
            
            if (firstLine)
            {
                keys = GenerateKeys(tokens);
                firstLine = false;

                bool allKeysOk = KeyExists(keys, KEY_STR_URL) && KeyExists(keys, KEY_STR_USERNAME) && KeyExists(keys, KEY_STR_PASSWORD);
                if (!allKeysOk)
                {
                    return false;
                }
            }
            else
            {
                logins.push_back(CsvLineToLogin(line, keys));
                success = true;
            }
        }
        catch(std::exception& ex)
        {
            std::cout << ex.what() << std::endl;
        }
        catch(...)
        {
            std::cout << current_exception().__cxa_exception_type()->name() << std::endl;
        }
    }

    return success;
}

bool csv::CSV_SetLoginsToFile(ofstream& file, const vector<passwords::Login_t>& logins)
{
    try 
    {
        file << OUTPUT_HEADER << endl;

        for (auto& login: logins)
        {
            file << LoginToCsvLine(login);
        }
    }
    catch (...)
    {
        return false;
    }

    return true;
}
