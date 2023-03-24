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

using namespace std;
using namespace fileops;

CryptFile::CryptFile(encryption::AESGCM& aes, std::fstream& file) : m_aes(aes), m_file(file)
{
    m_file.seekg(ios_base::beg);
}

CryptFile::~CryptFile()
{

}

bool CryptFile::Load(passwords::PasswordManager& manager)
{
    return false;
}

bool CryptFile::Save(passwords::PasswordManager& manager)
{
    return false;
}

bool CryptFile::Verify(ByteVector_t& data)
{
    (void)data;
    return true;
}
