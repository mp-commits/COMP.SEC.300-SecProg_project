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

typedef std::array<uint8_t, 16> AesGcm_Key128_t;
typedef std::array<uint8_t, 32> AesGcm_Key256_t;

class AesGcm 
{
public:
    AesGcm(AesGcm_Key128_t& key);
    AesGcm(AesGcm_Key256_t& key);
    ~AesGcm();

    bool encrypt(const std::vector<uint8_t>& data_in, std::vector<uint8_t>& data_out);

private:
    const enum
    {
        KEY_TYPE_128,
        KEY_TYPE_256
    } m_keyType;
    
    union key
    {
        key(AesGcm_Key128_t k) : k128(k) {}
        key(AesGcm_Key256_t k) : k256(k) {}
        AesGcm_Key128_t k128;
        AesGcm_Key256_t k256;
    } m_key;
    
};

} // namespace encryption
#endif // ENCRYPTION_HPP
