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

using namespace fileops;
using namespace passwords;
using namespace encryption;
using namespace encryptionUtil;
using namespace boost::json;

namespace passwords
{

void tag_invoke( const value_from_tag&, value& jv, Login_t const& l )
{
    // Assign a JSON value
    jv = {
        { "url", l.url },
        { "username", l.username },
        { "password", l.password },
        { "guid", l.guid }
    };
}

} // namespace passwords


static void MakeObject(const std::vector<Login_t>& logins, value& jv)
{
    storage_ptr sp = make_shared_resource<monotonic_resource>();
    jv = value_from(logins, sp);
}

CryptFile::CryptFile(const encryption::AESGCM& aes) : m_aes(aes)
{

}

CryptFile::~CryptFile()
{

}

bool CryptFile::Load(std::ifstream& file, passwords::PasswordManager& manager)
{
    return false;
}

bool CryptFile::Save(std::ofstream& file, const passwords::PasswordManager& manager)
{
    if (manager.Count() != 0)
    {   
        file.seekp(std::ios_base::beg);
        
        value jv;
        MakeObject(manager.GetLoginVector(), jv);

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
