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

#include <array>
#include <string>

#include "bytevector.hpp"

namespace encryption
{

typedef std::array<uint8_t, 16> ENCRYPTION_Key128_t;
typedef std::array<uint8_t, 24> ENCRYPTION_Key192_t;
typedef std::array<uint8_t, 32> ENCRYPTION_Key256_t;

void GenerateRandom(uint8_t* buffer, size_t count);

class EVPKDF 
{
public:
    EVPKDF(const std::string& pw, const ByteVector_t& salt);

    void derive128(ENCRYPTION_Key128_t& key);
    void derive192(ENCRYPTION_Key192_t& key);
    void derive256(ENCRYPTION_Key256_t& key);

private:
    std::string m_pw;
    ByteVector_t m_salt;
};

class AESGCM 
{
public:
    AESGCM(const ENCRYPTION_Key128_t& key);
    AESGCM(const ENCRYPTION_Key192_t& key);
    AESGCM(const ENCRYPTION_Key256_t& key);
    ~AESGCM();

    bool encrypt(const ByteVector_t& data_in, ByteVector_t& data_out);
    bool decrypt(const ByteVector_t& data_in, ByteVector_t& data_out);

    std::string encryptString(const std::string& input);
    std::string decryptString(const std::string& input);

private:
    const enum
    {
        KEY_TYPE_128,
        KEY_TYPE_192,
        KEY_TYPE_256
    } m_keyType;
    
    const union key
    {
        key(ENCRYPTION_Key128_t k) : k128(k) {}
        key(ENCRYPTION_Key192_t k) : k192(k) {}
        key(ENCRYPTION_Key256_t k) : k256(k) {}
        ENCRYPTION_Key128_t k128;
        ENCRYPTION_Key192_t k192;
        ENCRYPTION_Key256_t k256;
    } m_key;
};

} // namespace encryption
#endif // ENCRYPTION_HPP
