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

#include <iostream>

using namespace fileops;
using namespace passwords;
using namespace encryption;
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

CryptFile::CryptFile(const encryption::AESGCM& aes, std::fstream& file) : m_aes(aes), m_file(file)
{
    m_file.seekg(std::ios_base::beg);
}

CryptFile::~CryptFile()
{

}

bool CryptFile::Load(passwords::PasswordManager& manager)
{
    return false;
}

bool CryptFile::Save(const passwords::PasswordManager& manager)
{
    if (manager.Count() != 0)
    {
        value jv;
        MakeObject(manager.GetLoginVector(), jv);

        std::cout << jv << std::endl;

        ByteVector_t cryptData;
        ByteVector_t plainData(value_to<std::string>(jv).begin(), value_to<std::string>(jv).end());
        WriteChecksum(plainData);
        m_aes.encrypt(plainData, cryptData);

        for (auto c: cryptData)
        {
            m_file.put(c);
        }

        return m_file.good();
    }

    return false;
}

bool CryptFile::VerifyChecksum(ByteVector_t& data)
{
    (void)data;
    return true;
}

void CryptFile::WriteChecksum(ByteVector_t& data)
{
    (void)data;
}
