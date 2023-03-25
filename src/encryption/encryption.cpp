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

#include "encryption/sha256.hpp"
#include "encryption/encryption.hpp"
#include "encryption/util.hpp"

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <sstream>

using namespace encryption;
using namespace encryptionUtil;


#define IV_SIZE (AES_BLOCK_SIZE)
#define TAG_SIZE (AES_BLOCK_SIZE)
#define HEADER_SIZE (IV_SIZE + TAG_SIZE)

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

AESGCM::AESGCM(const AESGCM_Key128_t& key) : m_keyType(KEY_TYPE_128), m_key(key)
{
    InitSSL();
}

AESGCM::AESGCM(const AESGCM_Key192_t& key) : m_keyType(KEY_TYPE_192), m_key(key)
{
    InitSSL();
}

AESGCM::AESGCM(const AESGCM_Key256_t& key) : m_keyType(KEY_TYPE_256), m_key(key)
{
    InitSSL();
}

AESGCM::~AESGCM() {}

bool AESGCM::encrypt(const ByteVector_t& data_in, ByteVector_t& data_out)
{
    if (data_in.size() == 0)
    {
        return false;
    }

    size_t enc_length = data_in.size() * 3;
    data_out.resize(enc_length, 0x00);

    uint8_t tag[TAG_SIZE];
    uint8_t iv[IV_SIZE];

    RAND_bytes(iv, sizeof(iv));
    std::copy(iv, iv+IV_SIZE, data_out.begin()+IV_SIZE);

    int size = 0;
    int finalSize = 0;

    EVP_CIPHER_CTX* cipher = EVP_CIPHER_CTX_new();

    if (m_keyType == KEY_TYPE_128)
    {
        EVP_EncryptInit(cipher, EVP_aes_128_gcm(), m_key.k128.data(), iv);
    }
    else if (m_keyType == KEY_TYPE_192)
    {
        EVP_EncryptInit(cipher, EVP_aes_192_gcm(), m_key.k192.data(), iv);
    }
    else
    {
        EVP_EncryptInit(cipher, EVP_aes_256_gcm(), m_key.k256.data(), iv);
    }

    EVP_EncryptUpdate(cipher, &data_out.data()[HEADER_SIZE], &size, data_in.data(), data_in.size());
    EVP_EncryptFinal(cipher, &data_out.data()[HEADER_SIZE+size], &finalSize);
    EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_GET_TAG, 16, tag);

    std::copy( tag, tag+TAG_SIZE, data_out.begin());
    std::copy(iv, iv+IV_SIZE, data_out.begin()+IV_SIZE);
    data_out.resize(HEADER_SIZE + size + finalSize);

    EVP_CIPHER_CTX_free(cipher);

    return (size != 0);
}

bool AESGCM::decrypt(const ByteVector_t& data_in, ByteVector_t& data_out)
{
    if (data_in.size() == 0)
    {
        return false;
    }
    
    data_out.resize(data_in.size(), 0x00);

    uint8_t tag[AES_BLOCK_SIZE];
    uint8_t iv[AES_BLOCK_SIZE];

    std::copy(data_in.begin(), data_in.begin()+TAG_SIZE, tag);
    std::copy(data_in.begin()+TAG_SIZE, data_in.begin()+TAG_SIZE+IV_SIZE, iv);

    int size = 0;
    int finalSize = 0;

    EVP_CIPHER_CTX* cipher = EVP_CIPHER_CTX_new();

    if (m_keyType == KEY_TYPE_128)
    {
        EVP_DecryptInit(cipher, EVP_aes_128_gcm(), m_key.k128.data(), iv);
    }
    else if (m_keyType == KEY_TYPE_192)
    {
        EVP_DecryptInit(cipher, EVP_aes_192_gcm(), m_key.k128.data(), iv);
    }
    else
    {
        EVP_DecryptInit(cipher, EVP_aes_256_gcm(), m_key.k256.data(), iv);
    }

    EVP_DecryptUpdate(cipher, data_out.data(), &size, &data_in.data()[HEADER_SIZE], data_in.size() - HEADER_SIZE);
    EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_SET_TAG, 16, tag);
    EVP_DecryptFinal(cipher, &data_out.data()[size], &finalSize);
    EVP_CIPHER_CTX_free(cipher);

    data_out.resize(size + finalSize, 0x00);

    return (size != 0);
}

std::string AESGCM::encryptString(const std::string& input)
{
    ByteVector_t data_in = StringToVector(input);
    ByteVector_t data_out;

    encrypt(data_in, data_out);
    return vectorToString(data_out);
}

std::string AESGCM::decryptString(const std::string& input)
{
    ByteVector_t data_in = StringToVector(input);
    ByteVector_t data_out;

    decrypt(data_in, data_out);
    return vectorToString(data_out);
}

ByteVector_t encryption::CalculateSHA256(const ByteVector_t& data)
{
    ByteVector_t hash(SHA256_DIGEST_LENGTH);

    SHA256(data.data(), data.size(), hash.data());

    return hash;
}
