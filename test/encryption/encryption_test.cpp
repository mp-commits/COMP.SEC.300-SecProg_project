/**
 * @file encryption_test.cpp
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-03-18
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include "gtest/gtest.h"
#include <random>
#include <climits>

#include "encryption/encryption.hpp"

using namespace encryption;
using std::vector;
using std::string;
using random_bytes_engine = std::independent_bits_engine<
    std::default_random_engine, CHAR_BIT, unsigned char>;

#define TEST_SUITE_NAME EncryptionTest

static void CompareVectors(const ByteVector_t& a, const ByteVector_t& b)
{
    ASSERT_EQ(a.size(), b.size());

    for (size_t i = 0; i < a.size(); i++)
    {
        EXPECT_EQ(a[i], b[i]);
    }
}

TEST(TEST_SUITE_NAME, deriveKey)
{
    const string password = "SecretKey";
    const ByteVector_t salt = {1, 3, 5, 7, 9};
    const ByteVector_t salt2 = {1, 2, 5, 7, 9};

    EVPKDF der(password, salt);
    EVPKDF der2(password, salt);
    EVPKDF der3(password, salt2);

    ENCRYPTION_Key128_t key;
    der.derive128(key);
    ENCRYPTION_Key128_t key2;
    der2.derive128(key2);
    ENCRYPTION_Key128_t key3;
    der3.derive128(key3);

    EXPECT_EQ(key, key2);
    EXPECT_NE(key, key3);
}

TEST(TEST_SUITE_NAME, invalidInput)
{
    ByteVector_t empty(0);
    ByteVector_t output = {1, 2, 3, 4};
    const ByteVector_t reference(output);
    ENCRYPTION_Key128_t key;

    AESGCM aes(key);
    EXPECT_FALSE(aes.encrypt(empty, output));

    // Ouput data must not be modified if operation was unsuccessful
    CompareVectors(output, reference);

    EXPECT_FALSE(aes.decrypt(empty, output));
}

TEST(TEST_SUITE_NAME, aes128keyEncryptBytesBasic)
{
    const ENCRYPTION_Key128_t key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};

    const ByteVector_t testData = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    ByteVector_t encryptedData;

    AESGCM crypter(key);

    EXPECT_TRUE(crypter.encrypt(testData, encryptedData));
    EXPECT_NE(testData, encryptedData);

    ByteVector_t plainData;
    EXPECT_TRUE(crypter.decrypt(encryptedData, plainData));

    CompareVectors(testData, plainData);
}

TEST(TEST_SUITE_NAME, aes128keyEncryptBytesLongData)
{
    constexpr size_t TEST_DATA_LENGTH = 1024 * 1024; // 1 MB
    const ENCRYPTION_Key128_t key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    AESGCM crypter(key);

    ByteVector_t testData(TEST_DATA_LENGTH, 0x00);
    ByteVector_t encryptedData;

    random_bytes_engine rbe;
    std::generate(begin(testData), end(testData), std::ref(rbe));

    EXPECT_TRUE(crypter.encrypt(testData, encryptedData));
    EXPECT_NE(testData, encryptedData);

    ByteVector_t plainData;
    EXPECT_TRUE(crypter.decrypt(encryptedData, plainData));

    CompareVectors(testData, plainData);
}

TEST(TEST_SUITE_NAME, aes128keyEncryptBytesMultiInstance)
{
    const ENCRYPTION_Key128_t key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    const ByteVector_t testData = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    ByteVector_t encryptedData;

    AESGCM encrypter(key);

    EXPECT_TRUE(encrypter.encrypt(testData, encryptedData));
    EXPECT_NE(testData, encryptedData);

    ByteVector_t plainData;
    AESGCM decrypter(key);
    EXPECT_TRUE(decrypter.decrypt(encryptedData, plainData));

    CompareVectors(testData, plainData);

    ByteVector_t plainData2;
    AESGCM decrypter2(key);
    EXPECT_TRUE(decrypter2.decrypt(encryptedData, plainData2));

    CompareVectors(testData, plainData2);
}

TEST(TEST_SUITE_NAME, aes128keyEncryptBytesLongDataMultiInstance)
{
    constexpr size_t TEST_DATA_LENGTH = 1024 * 1024; // 1 MB
    const ENCRYPTION_Key128_t key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    AESGCM encrypter(key);

    ByteVector_t testData(TEST_DATA_LENGTH, 0x00);
    ByteVector_t encryptedData;

    random_bytes_engine rbe;
    std::generate(begin(testData), end(testData), std::ref(rbe));

    EXPECT_TRUE(encrypter.encrypt(testData, encryptedData));
    EXPECT_NE(testData, encryptedData);

    AESGCM decrypter(key);

    ByteVector_t plainData;
    EXPECT_TRUE(decrypter.decrypt(encryptedData, plainData));

    CompareVectors(testData, plainData);
}

TEST(TEST_SUITE_NAME, aes128WrongKey)
{
    const ENCRYPTION_Key128_t key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    const ENCRYPTION_Key128_t wrongKey = {0};

    const ByteVector_t testData = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    ByteVector_t encryptedData;

    AESGCM encrypter(key);
    AESGCM decrypter(wrongKey);

    EXPECT_TRUE(encrypter.encrypt(testData, encryptedData));
    EXPECT_NE(testData, encryptedData);

    ByteVector_t plainData;
    EXPECT_FALSE(decrypter.decrypt(encryptedData, plainData));
    EXPECT_NE(testData, plainData);

    EXPECT_TRUE(encrypter.decrypt(encryptedData, plainData));
    CompareVectors(testData, plainData);
}

TEST(TEST_SUITE_NAME, aes256keyEncryptBytesBasic)
{
    const ENCRYPTION_Key256_t key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};

    const ByteVector_t testData = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    ByteVector_t encryptedData;

    AESGCM crypter(key);

    EXPECT_TRUE(crypter.encrypt(testData, encryptedData));
    EXPECT_NE(testData, encryptedData);

    ByteVector_t plainData;
    EXPECT_TRUE(crypter.decrypt(encryptedData, plainData));

    CompareVectors(testData, plainData);
}

TEST(TEST_SUITE_NAME, aes256keyEncryptBytesLongData)
{
    constexpr size_t TEST_DATA_LENGTH = 1024 * 1024; // 1 MB
    const ENCRYPTION_Key256_t key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    AESGCM crypter(key);

    ByteVector_t testData(TEST_DATA_LENGTH, 0x00);
    ByteVector_t encryptedData;

    random_bytes_engine rbe;
    std::generate(begin(testData), end(testData), std::ref(rbe));

    EXPECT_TRUE(crypter.encrypt(testData, encryptedData));
    EXPECT_NE(testData, encryptedData);

    ByteVector_t plainData;
    EXPECT_TRUE(crypter.decrypt(encryptedData, plainData));

    CompareVectors(testData, plainData);
}

TEST(TEST_SUITE_NAME, aes256keyEncryptBytesMultiInstance)
{
    const ENCRYPTION_Key256_t key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    const ByteVector_t testData = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    ByteVector_t encryptedData;

    AESGCM encrypter(key);

    EXPECT_TRUE(encrypter.encrypt(testData, encryptedData));
    EXPECT_NE(testData, encryptedData);

    ByteVector_t plainData;
    AESGCM decrypter(key);
    EXPECT_TRUE(decrypter.decrypt(encryptedData, plainData));

    CompareVectors(testData, plainData);

    ByteVector_t plainData2;
    AESGCM decrypter2(key);
    EXPECT_TRUE(decrypter2.decrypt(encryptedData, plainData2));

    CompareVectors(testData, plainData2);
}

TEST(TEST_SUITE_NAME, aes256keyEncryptBytesLongDataMultiInstance)
{
    constexpr size_t TEST_DATA_LENGTH = 1024 * 1024; // 1 MB
    const ENCRYPTION_Key256_t key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    AESGCM encrypter(key);

    ByteVector_t testData(TEST_DATA_LENGTH, 0x00);
    ByteVector_t encryptedData;

    random_bytes_engine rbe;
    std::generate(begin(testData), end(testData), std::ref(rbe));

    EXPECT_TRUE(encrypter.encrypt(testData, encryptedData));
    EXPECT_NE(testData, encryptedData);

    AESGCM decrypter(key);

    ByteVector_t plainData;
    EXPECT_TRUE(decrypter.decrypt(encryptedData, plainData));

    CompareVectors(testData, plainData);
}

TEST(TEST_SUITE_NAME, aes256WrongKey)
{
    const ENCRYPTION_Key256_t key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    const ENCRYPTION_Key256_t wrongKey = {0};

    const ByteVector_t testData = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    ByteVector_t encryptedData;

    AESGCM encrypter(key);
    AESGCM decrypter(wrongKey);

    EXPECT_TRUE(encrypter.encrypt(testData, encryptedData));
    EXPECT_NE(testData, encryptedData);

    ByteVector_t plainData;
    EXPECT_FALSE(decrypter.decrypt(encryptedData, plainData));
    EXPECT_NE(testData, plainData);

    EXPECT_TRUE(encrypter.decrypt(encryptedData, plainData));
    CompareVectors(testData, plainData);
}

TEST(TEST_SUITE_NAME, aes192keyEncryptBytesBasic)
{
    const ENCRYPTION_Key192_t key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,3,4,5,6,7,8};

    const ByteVector_t testData = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,3,4,5,6,7,8};
    ByteVector_t encryptedData;

    AESGCM crypter(key);

    EXPECT_TRUE(crypter.encrypt(testData, encryptedData));
    EXPECT_NE(testData, encryptedData);

    ByteVector_t plainData;
    EXPECT_TRUE(crypter.decrypt(encryptedData, plainData));

    CompareVectors(testData, plainData);
}

TEST(TEST_SUITE_NAME, aes192keyEncryptBytesLongData)
{
    constexpr size_t TEST_DATA_LENGTH = 1024 * 1024; // 1 MB
    const ENCRYPTION_Key192_t key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,3,4,5,6,7,8};
    AESGCM crypter(key);

    ByteVector_t testData(TEST_DATA_LENGTH, 0x00);
    ByteVector_t encryptedData;

    random_bytes_engine rbe;
    std::generate(begin(testData), end(testData), std::ref(rbe));

    EXPECT_TRUE(crypter.encrypt(testData, encryptedData));
    EXPECT_NE(testData, encryptedData);

    ByteVector_t plainData;
    EXPECT_TRUE(crypter.decrypt(encryptedData, plainData));

    CompareVectors(testData, plainData);
}

TEST(TEST_SUITE_NAME, aes192keyEncryptBytesMultiInstance)
{
    const ENCRYPTION_Key192_t key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,3,4,5,6,7,8};
    const ByteVector_t testData = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,3,4,5,6,7,8};
    ByteVector_t encryptedData;

    AESGCM encrypter(key);

    EXPECT_TRUE(encrypter.encrypt(testData, encryptedData));
    EXPECT_NE(testData, encryptedData);

    ByteVector_t plainData;
    AESGCM decrypter(key);
    EXPECT_TRUE(decrypter.decrypt(encryptedData, plainData));

    CompareVectors(testData, plainData);

    ByteVector_t plainData2;
    AESGCM decrypter2(key);
    EXPECT_TRUE(decrypter2.decrypt(encryptedData, plainData2));

    CompareVectors(testData, plainData2);
}

TEST(TEST_SUITE_NAME, aes192keyEncryptBytesLongDataMultiInstance)
{
    constexpr size_t TEST_DATA_LENGTH = 1024 * 1024; // 1 MB
    const ENCRYPTION_Key192_t key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,3,4,5,6,7,8};
    AESGCM encrypter(key);

    ByteVector_t testData(TEST_DATA_LENGTH, 0x00);
    ByteVector_t encryptedData;

    random_bytes_engine rbe;
    std::generate(begin(testData), end(testData), std::ref(rbe));

    EXPECT_TRUE(encrypter.encrypt(testData, encryptedData));
    EXPECT_NE(testData, encryptedData);

    AESGCM decrypter(key);

    ByteVector_t plainData;
    EXPECT_TRUE(decrypter.decrypt(encryptedData, plainData));

    CompareVectors(testData, plainData);
}

TEST(TEST_SUITE_NAME, aes192WrongKey)
{
    const ENCRYPTION_Key192_t key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,3,4,5,6,7,8};
    const ENCRYPTION_Key192_t wrongKey = {0};

    const ByteVector_t testData = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,3,4,5,6,7,8};
    ByteVector_t encryptedData;

    AESGCM encrypter(key);
    AESGCM decrypter(wrongKey);

    EXPECT_TRUE(encrypter.encrypt(testData, encryptedData));
    EXPECT_NE(testData, encryptedData);

    ByteVector_t plainData;
    EXPECT_FALSE(decrypter.decrypt(encryptedData, plainData));
    EXPECT_NE(testData, plainData);

    EXPECT_TRUE(encrypter.decrypt(encryptedData, plainData));
    CompareVectors(testData, plainData);
}
