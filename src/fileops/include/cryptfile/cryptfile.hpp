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

#include <istream>
#include <ostream>
#include "encryption/encryption.hpp"
#include "manager/manager.hpp"
#include "bytevector.hpp"

namespace fileops {

class CryptFile 
{
public:
    CryptFile(const std::string& password);
    ~CryptFile();

    bool Load(std::istream& file, std::vector<passwords::Login_t>& logins);
    bool Save(std::ostream& file, const std::vector<passwords::Login_t>& logins);

private:
    std::string         m_password;

    bool VerifyChecksum(ByteVector_t& data);
    void WriteChecksum(ByteVector_t& data);
};

} // namespace fileops

#endif // CRYPTFILE_HPP
