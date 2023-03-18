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

typedef std::array<uint8_t, 16> AesGcm_Key128_t;
typedef std::array<uint8_t, 32> AesGcm_Key256_t;

class AesGcm 
{
public:
    AesGcm(const AesGcm_Key128_t& key);
    AesGcm(const AesGcm_Key256_t& key);
    ~AesGcm();

    bool encrypt(const ByteVector_t& data_in, ByteVector_t& data_out);
    bool decrypt(const ByteVector_t& data_in, ByteVector_t& data_out);

    std::string encryptString(const std::string& input);
    std::string decryptString(const std::string& input);

private:
    const enum
    {
        KEY_TYPE_128,
        KEY_TYPE_256
    } m_keyType;
    
    const union key
    {
        key(AesGcm_Key128_t k) : k128(k) {}
        key(AesGcm_Key256_t k) : k256(k) {}
        AesGcm_Key128_t k128;
        AesGcm_Key256_t k256;
    } m_key;
    
    std::string vectorToString(const ByteVector_t& data_in);
    ByteVector_t StringToVector(const std::string& string_in);
};

} // namespace encryption
#endif // ENCRYPTION_HPP
