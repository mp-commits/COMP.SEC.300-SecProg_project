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

#include "cryptfile/cryptfile.hpp"
#include "boost/json.hpp"
#include "encryption/sha256.hpp"
#include "encryption/util.hpp"

#include <iostream>
#include <sstream>
#include <iomanip>

using namespace fileops;
using namespace passwords;
using namespace encryption;
using namespace encryptionUtil;
using namespace boost::json;

namespace passwords
{

void tag_invoke(const value_from_tag&, value& jv, Login_t const& l )
{
    // Assign a JSON value
    jv = {
        { "url", l.url },
        { "username", l.username },
        { "password", l.password },
        { "guid", l.guid }
    };
}

std::string AttemptToGetString(const value& jv, const std::string keyword)
{
    if (jv.is_object())
    {
        if (jv.as_object().if_contains(keyword))
        {
            if (jv.at(keyword).is_string())
            {
                return jv.at(keyword).as_string().c_str();
            }
        }
    }
    return "";
}

Login_t tag_invoke(const value_to_tag<Login_t>&, const value& jv)
{
    std::string username = AttemptToGetString(jv, "username");
    std::string url = AttemptToGetString(jv, "url");
    std::string password = AttemptToGetString(jv, "password");
    std::string guid = AttemptToGetString(jv, "guid");

    return Login_t(url, username, password, guid);
}

} // namespace passwords


static void MakeObject(const std::vector<Login_t>& logins, value& jv)
{
    storage_ptr sp = make_shared_resource<monotonic_resource>();
    jv = value_from(logins, sp);
}

static void MakeLogins(const value& jv, std::vector<Login_t>& logins)
{
    for (auto val: jv.as_array())
    {
        Login_t login = value_to<Login_t>(val);
        logins.push_back(login);
    }
}

CryptFile::CryptFile(const encryption::AESGCM& aes) : m_aes(aes)
{

}

CryptFile::~CryptFile()
{

}

bool CryptFile::Load(std::ifstream& file, std::vector<passwords::Login_t>& logins, std::string& errorString)
{
    file.seekg(0, std::ios_base::end);
    size_t length = file.tellg();
    file.seekg(0, std::ios_base::beg);

    ByteVector_t cryptData(length);
    ByteVector_t plainData;

    file.read((char*)cryptData.data(), length);

    if (!m_aes.decrypt(cryptData, plainData))
    {
        errorString += "Deryption failed";
        return false;
    }
    if (!VerifyChecksum(plainData))
    {
        errorString += "Checksum failed";
        return false;
    }
    
    std::string s = vectorToString(plainData);
    value jv = parse(s);

    std::cout << jv << std::endl;
    MakeLogins(jv, logins);
    
    return true;
}

bool CryptFile::Save(std::ofstream& file, const std::vector<passwords::Login_t>& logins, std::string& errorString)
{
    if (!logins.empty())
    {   
        file.seekp(std::ios_base::beg);
        
        value jv;
        MakeObject(logins, jv);

        std::cout << jv << std::endl;

        std::stringstream ss;
        ss << jv;

        ByteVector_t cryptData;
        ByteVector_t plainData = StringToVector(ss.str());

        WriteChecksum(plainData);
        m_aes.encrypt(plainData, cryptData);

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
