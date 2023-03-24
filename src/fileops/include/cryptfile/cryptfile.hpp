/**
 * @file cryptfile.hpp
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-03-23
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef CRYPTFILE_HPP
#define CRYPTFILE_HPP

#include <fstream>
#include "encryption/encryption.hpp"
#include "passwords/passwords.hpp"
#include "bytevector.hpp"

namespace fileops {

class CryptFile 
{
public:
    CryptFile(encryption::AESGCM& aes, std::fstream& file);
    ~CryptFile();

    bool Load(passwords::PasswordManager& manager);
    bool Save(passwords::PasswordManager& manager);

private:
    encryption::AESGCM m_aes;
    std::fstream& m_file;

    bool Verify(ByteVector_t& data);
};

} // namespace fileops
#endif
