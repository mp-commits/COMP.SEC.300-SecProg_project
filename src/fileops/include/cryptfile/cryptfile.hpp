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
    CryptFile(const encryption::AESGCM& aes);
    ~CryptFile();

    bool Load(std::ifstream& file, std::vector<passwords::Login_t>& logins, std::string& errorString);
    bool Save(std::ofstream& file, const std::vector<passwords::Login_t>& logins, std::string& errorString);

private:
    encryption::AESGCM m_aes;

    bool VerifyChecksum(ByteVector_t& data);
    void WriteChecksum(ByteVector_t& data);
};

} // namespace fileops
#endif
