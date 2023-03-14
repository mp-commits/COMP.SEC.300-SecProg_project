/**
 * @file encryption.hpp
 * @author Mikael Penttinen
 * @brief 
 * @version 0.1
 * @date 2023-03-14
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef ENCRYPTION_HPP
#define ENCRYPTION_HPP

#include <stdint.h>
#include <vector>
#include <array>

namespace encryption
{

typedef std::array<uint8_t, 16> CrypterKey128_t;
typedef std::array<uint8_t, 32> CrypterKey256_t;

class Crypter 
{
public:
    Crypter(CrypterKey128_t& key);
    Crypter(CrypterKey256_t& key);
    ~Crypter();

    bool encrypt(const std::vector<uint8_t>& data_in, std::vector<uint8_t>& data_out);

private:
    typedef enum
    {
        KEY_TYPE_128,
        KEY_TYPE_256
    } KeyType_t;

    const KeyType_t m_keyType;
    CrypterKey128_t m_key128;
    CrypterKey256_t m_key256;
};

} // namespace encryption
#endif // ENCRYPTION_HPP
