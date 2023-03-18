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
    if (data_in.size() == 0)
    {
        return false;
    }

    size_t enc_length = data_in.size() * 3;
    data_out.resize(enc_length, 0x00);

    uint8_t tag[AES_BLOCK_SIZE];
    uint8_t iv[AES_BLOCK_SIZE];

    RAND_bytes(iv, sizeof(iv));
    std::copy(iv, iv+16, data_out.begin()+16);

    int size = 0;
    int finalSize = 0;

    EVP_CIPHER_CTX* cipher = EVP_CIPHER_CTX_new();

    if (m_keyType == KEY_TYPE_128)
    {
        EVP_EncryptInit(cipher, EVP_aes_128_gcm(), m_key.k128.data(), iv);
    }
    else
    {
        EVP_EncryptInit(cipher, EVP_aes_256_gcm(), m_key.k256.data(), iv);
    }

    EVP_EncryptUpdate(cipher, &data_out.data()[32], &size, data_in.data(), data_in.size());
    EVP_EncryptFinal(cipher, &data_out.data()[32+size], &finalSize);
    EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_GET_TAG, 16, tag);

    std::copy( tag, tag+16, data_out.begin());
    std::copy(iv, iv+16, data_out.begin()+16);
    data_out.resize(32 + size + finalSize);

    EVP_CIPHER_CTX_free(cipher);

    return (size != 0) && (finalSize != 0);
}

bool AesGcm::decrypt(const std::vector<uint8_t>& data_in, std::vector<uint8_t>& data_out)
{
    if (data_in.size() == 0)
    {
        return false;
    }
    
    data_out.resize(data_in.size(), 0x00);

    uint8_t tag[AES_BLOCK_SIZE];
    uint8_t iv[AES_BLOCK_SIZE];

    std::copy(data_in.begin(), data_in.begin()+16, tag);
    std::copy(data_in.begin()+16, data_in.begin()+32, iv);

    int size = 0;
    int finalSize = 0;

    EVP_CIPHER_CTX* cipher = EVP_CIPHER_CTX_new();

    if (m_keyType == KEY_TYPE_128)
    {
        EVP_DecryptInit(cipher, EVP_aes_128_gcm(), m_key.k128.data(), iv);
    }
    else
    {
        EVP_DecryptInit(cipher, EVP_aes_256_gcm(), m_key.k256.data(), iv);
    }

    EVP_DecryptUpdate(cipher, data_out.data(), &size, &data_in.data()[32], data_in.size() - 32);
    EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_SET_TAG, 16, tag);
    EVP_DecryptFinal(cipher, &data_out.data()[size], &finalSize);
    EVP_CIPHER_CTX_free(cipher);

    data_out.resize(size + finalSize, 0x00);

    return (size != 0) && (finalSize != 0);
}

std::string AesGcm::encryptString(const std::string& input)
{
    std::vector<uint8_t> data_in = StringToVector(input);
    std::vector<uint8_t> data_out;

    encrypt(data_in, data_out);
    return vectorToString(data_out);
}

std::string AesGcm::decryptString(const std::string& input)
{
    std::vector<uint8_t> data_in = StringToVector(input);
    std::vector<uint8_t> data_out;

    decrypt(data_in, data_out);
    return vectorToString(data_out);
}

std::string AesGcm::vectorToString(const std::vector<uint8_t>& data_in)
{
    std::string result = "";

    for (uint8_t byte : data_in)
    {
        result.push_back(byte);
    }

    return result;
}

std::vector<uint8_t> AesGcm::StringToVector(const std::string& string_in)
{
    std::vector<uint8_t> result;

    for (char byte : string_in)
    {
        result.push_back(byte);
    }

    return result;
}
