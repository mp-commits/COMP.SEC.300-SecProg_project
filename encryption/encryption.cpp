/**
 * @file encryption.cpp
 * @author Mikael Penttinen
 * @brief 
 * @version 0.1
 * @date 2023-03-14
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include "encryption/encryption.hpp"

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace encryption;

static bool f_ssl_init_done = false;

static void InitSSL()
{
    if (!f_ssl_init_done)
    {
        OpenSSL_add_all_ciphers();
        (void)RAND_load_file("/dev/urandom", 32);
        f_ssl_init_done = true;
    }
}

AesGcm::AesGcm(AesGcm_Key128_t& key) : m_keyType(KEY_TYPE_128), m_key(key)
{
    InitSSL();
}

AesGcm::AesGcm(AesGcm_Key256_t& key) : m_keyType(KEY_TYPE_256), m_key(key)
{
    InitSSL();
}

AesGcm::~AesGcm() {}

bool AesGcm::encrypt(const std::vector<uint8_t>& data_in, std::vector<uint8_t>& data_out)
{
    size_t enc_length = data_in.size() * 3;
    data_out.resize(enc_length, 0x00);

    uint8_t tag[AES_BLOCK_SIZE];
    uint8_t iv[AES_BLOCK_SIZE];

    RAND_bytes(iv, sizeof(iv));
    std::copy(iv, iv+16, data_out.begin()+16);

    return true;
}
