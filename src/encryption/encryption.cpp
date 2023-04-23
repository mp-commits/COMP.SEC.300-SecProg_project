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
#include <openssl/kdf.h>
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

void encryption::GenerateRandom(uint8_t* buffer, size_t count)
{
    if (buffer)
    {
        RAND_bytes(buffer, count);
    }
}

template<size_t N>
void DeriveKey(std::array<uint8_t, N>& derived, std::string& pw, ByteVector_t& salt)
{
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx = nullptr;
    OSSL_PARAM params[5], *p = params;

    /* Find and allocate a context for the HKDF algorithm */
    if ((kdf = EVP_KDF_fetch(nullptr, "hkdf", nullptr)) == nullptr) {
        std::runtime_error("EVP_KDF_fetch");
    }

    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);    /* The kctx keeps a reference so this is safe */
    if (kctx == nullptr) {
        std::runtime_error("EVP_KDF_CTX_new");
    }

    std::string digest = "sha256";
    std::string label = "label";

    /* Build up the parameters for the derivation */
    *p++ = OSSL_PARAM_construct_utf8_string("digest", digest.data(), digest.size());
    *p++ = OSSL_PARAM_construct_octet_string("salt", reinterpret_cast<void*>(salt.data()), salt.size());
    *p++ = OSSL_PARAM_construct_octet_string("key", reinterpret_cast<void*>(pw.data()), pw.size());
    *p++ = OSSL_PARAM_construct_octet_string("info", reinterpret_cast<void*>(label.data()), label.size());
    *p = OSSL_PARAM_construct_end();

    if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
        EVP_KDF_CTX_free(kctx);
        std::runtime_error("EVP_KDF_CTX_set_params");
    }

    /* Do the derivation */
    if (EVP_KDF_derive(kctx, derived.data(), derived.size(), nullptr) <= 0) {
        EVP_KDF_CTX_free(kctx);
        std::runtime_error("EVP_KDF_derive");
    }

    EVP_KDF_CTX_free(kctx);
}

EVPKDF::EVPKDF(const std::string& pw, const ByteVector_t& salt) : m_pw(pw), m_salt(salt)
{
    InitSSL();
}

ENCRYPTION_Key128_t EVPKDF::derive128()
{
    ENCRYPTION_Key128_t key;
    DeriveKey<key.size()>(key, m_pw, m_salt);
    return key;
}

ENCRYPTION_Key192_t EVPKDF::derive192()
{
    ENCRYPTION_Key192_t key;
    DeriveKey<key.size()>(key, m_pw, m_salt);
    return key;
}

ENCRYPTION_Key256_t EVPKDF::derive256()
{
    ENCRYPTION_Key256_t key;
    DeriveKey<key.size()>(key, m_pw, m_salt);
    return key;
}


AESGCM::AESGCM(const ENCRYPTION_Key128_t& key) : m_keyType(KEY_TYPE_128), m_key(key)
{
    InitSSL();
}

AESGCM::AESGCM(const ENCRYPTION_Key192_t& key) : m_keyType(KEY_TYPE_192), m_key(key)
{
    InitSSL();
}

AESGCM::AESGCM(const ENCRYPTION_Key256_t& key) : m_keyType(KEY_TYPE_256), m_key(key)
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

    if (RAND_bytes(iv, sizeof(iv)) == 0)
    {
        std::runtime_error("RAND_bytes");
    }

    std::copy(iv, iv+IV_SIZE, data_out.begin()+IV_SIZE);

    int size = 0;
    int finalSize = 0;

    EVP_CIPHER_CTX* cipher = EVP_CIPHER_CTX_new();

    if (cipher == nullptr)
    {
        std::runtime_error("EVP_CIPHER_CTX_new");
    }

    int ret = 0;

    if (m_keyType == KEY_TYPE_128)
    {
        ret = EVP_EncryptInit(cipher, EVP_aes_128_gcm(), m_key.k128.data(), iv);
    }
    else if (m_keyType == KEY_TYPE_192)
    {
        ret = EVP_EncryptInit(cipher, EVP_aes_192_gcm(), m_key.k192.data(), iv);
    }
    else
    {
        ret = EVP_EncryptInit(cipher, EVP_aes_256_gcm(), m_key.k256.data(), iv);
    }

    if (ret == 0)
    {
        EVP_CIPHER_CTX_free(cipher);
        std::runtime_error("EVP_EncryptInit");
    }

    if ((EVP_EncryptUpdate(cipher, &data_out.data()[HEADER_SIZE], &size, data_in.data(), data_in.size()) == 0)
        || (EVP_EncryptFinal(cipher, &data_out.data()[HEADER_SIZE+size], &finalSize) == 0)
        || (EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_GET_TAG, 16, tag) == 0))
    {
        EVP_CIPHER_CTX_free(cipher);
        std::runtime_error("EVP_EncryptUpdate or EVP_EncryptFinal or EVP_CIPHER_CTX_ctrl");
    }

    std::copy(tag, tag+TAG_SIZE, data_out.begin());
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

    if (cipher == nullptr)
    {
        std::runtime_error("EVP_CIPHER_CTX_new");
    }

    int ret = 0;

    if (m_keyType == KEY_TYPE_128)
    {
        ret = EVP_DecryptInit(cipher, EVP_aes_128_gcm(), m_key.k128.data(), iv);
    }
    else if (m_keyType == KEY_TYPE_192)
    {
        ret = EVP_DecryptInit(cipher, EVP_aes_192_gcm(), m_key.k128.data(), iv);
    }
    else
    {
        ret = EVP_DecryptInit(cipher, EVP_aes_256_gcm(), m_key.k256.data(), iv);
    }

    if (ret == 0)
    {
        EVP_CIPHER_CTX_free(cipher);
        std::runtime_error("EVP_EncryptInit");
    }

    if ((EVP_DecryptUpdate(cipher, data_out.data(), &size, &data_in.data()[HEADER_SIZE], data_in.size() - HEADER_SIZE) == 0)
        || (EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_SET_TAG, 16, tag) == 0)
        || (EVP_DecryptFinal(cipher, &data_out.data()[size], &finalSize) == 0))
    {
        EVP_CIPHER_CTX_free(cipher);
        std::runtime_error("EVP_DecryptUpdate or EVP_DecryptFinal or EVP_CIPHER_CTX_ctrl");
    }

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
