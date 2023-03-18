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

TEST(TEST_SUITE_NAME, invalidInput)
{
    ByteVector_t empty(0);
    ByteVector_t output = {1, 2, 3, 4};
    const ByteVector_t reference(output);
    AesGcm_Key128_t key;

    AesGcm aes(key);
    EXPECT_FALSE(aes.encrypt(empty, output));

    // Ouput data must not be modified if operation was unsuccessful
    CompareVectors(output, reference);

    EXPECT_FALSE(aes.decrypt(empty, output));
}

TEST(TEST_SUITE_NAME, aes128keyEncryptBytesBasic)
{
    const AesGcm_Key128_t key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};

    const ByteVector_t testData = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    ByteVector_t encryptedData;

    AesGcm crypter(key);

    EXPECT_TRUE(crypter.encrypt(testData, encryptedData));
    EXPECT_NE(testData, encryptedData);

    ByteVector_t plainData;
    EXPECT_TRUE(crypter.decrypt(encryptedData, plainData));

    CompareVectors(testData, plainData);
}

TEST(TEST_SUITE_NAME, aes128keyEncryptBytesLongData)
{
    constexpr size_t TEST_DATA_LENGTH = 1024 * 1024; // 1 MB
    const AesGcm_Key128_t key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    AesGcm crypter(key);

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
    const AesGcm_Key128_t key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    const ByteVector_t testData = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    ByteVector_t encryptedData;

    AesGcm encrypter(key);

    EXPECT_TRUE(encrypter.encrypt(testData, encryptedData));
    EXPECT_NE(testData, encryptedData);

    ByteVector_t plainData;
    AesGcm decrypter(key);
    EXPECT_TRUE(decrypter.decrypt(encryptedData, plainData));

    CompareVectors(testData, plainData);

    ByteVector_t plainData2;
    AesGcm decrypter2(key);
    EXPECT_TRUE(decrypter2.decrypt(encryptedData, plainData2));

    CompareVectors(testData, plainData2);
}

TEST(TEST_SUITE_NAME, aes128keyEncryptBytesLongDataMultiInstance)
{
    constexpr size_t TEST_DATA_LENGTH = 1024 * 1024; // 1 MB
    const AesGcm_Key128_t key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    AesGcm encrypter(key);

    ByteVector_t testData(TEST_DATA_LENGTH, 0x00);
    ByteVector_t encryptedData;

    random_bytes_engine rbe;
    std::generate(begin(testData), end(testData), std::ref(rbe));

    EXPECT_TRUE(encrypter.encrypt(testData, encryptedData));
    EXPECT_NE(testData, encryptedData);

    AesGcm decrypter(key);

    ByteVector_t plainData;
    EXPECT_TRUE(decrypter.decrypt(encryptedData, plainData));

    CompareVectors(testData, plainData);
}

TEST(TEST_SUITE_NAME, aes128WrongKey)
{
    const AesGcm_Key128_t key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    const AesGcm_Key128_t wrongKey = {0};

    const ByteVector_t testData = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    ByteVector_t encryptedData;

    AesGcm encrypter(key);
    AesGcm decrypter(wrongKey);

    EXPECT_TRUE(encrypter.encrypt(testData, encryptedData));
    EXPECT_NE(testData, encryptedData);

    ByteVector_t plainData;
    EXPECT_TRUE(decrypter.decrypt(encryptedData, plainData));
    EXPECT_NE(testData, plainData);

    EXPECT_TRUE(encrypter.decrypt(encryptedData, plainData));
    CompareVectors(testData, plainData);
}

TEST(TEST_SUITE_NAME, aes256keyEncryptBytesBasic)
{
    const AesGcm_Key256_t key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};

    const ByteVector_t testData = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    ByteVector_t encryptedData;

    AesGcm crypter(key);

    EXPECT_TRUE(crypter.encrypt(testData, encryptedData));
    EXPECT_NE(testData, encryptedData);

    ByteVector_t plainData;
    EXPECT_TRUE(crypter.decrypt(encryptedData, plainData));

    CompareVectors(testData, plainData);
}

TEST(TEST_SUITE_NAME, aes256keyEncryptBytesLongData)
{
    constexpr size_t TEST_DATA_LENGTH = 1024 * 1024; // 1 MB
    const AesGcm_Key256_t key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    AesGcm crypter(key);

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
    const AesGcm_Key256_t key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    const ByteVector_t testData = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    ByteVector_t encryptedData;

    AesGcm encrypter(key);

    EXPECT_TRUE(encrypter.encrypt(testData, encryptedData));
    EXPECT_NE(testData, encryptedData);

    ByteVector_t plainData;
    AesGcm decrypter(key);
    EXPECT_TRUE(decrypter.decrypt(encryptedData, plainData));

    CompareVectors(testData, plainData);

    ByteVector_t plainData2;
    AesGcm decrypter2(key);
    EXPECT_TRUE(decrypter2.decrypt(encryptedData, plainData2));

    CompareVectors(testData, plainData2);
}

TEST(TEST_SUITE_NAME, aes256keyEncryptBytesLongDataMultiInstance)
{
    constexpr size_t TEST_DATA_LENGTH = 1024 * 1024; // 1 MB
    const AesGcm_Key256_t key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    AesGcm encrypter(key);

    ByteVector_t testData(TEST_DATA_LENGTH, 0x00);
    ByteVector_t encryptedData;

    random_bytes_engine rbe;
    std::generate(begin(testData), end(testData), std::ref(rbe));

    EXPECT_TRUE(encrypter.encrypt(testData, encryptedData));
    EXPECT_NE(testData, encryptedData);

    AesGcm decrypter(key);

    ByteVector_t plainData;
    EXPECT_TRUE(decrypter.decrypt(encryptedData, plainData));

    CompareVectors(testData, plainData);
}

TEST(TEST_SUITE_NAME, aes256WrongKey)
{
    const AesGcm_Key256_t key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    const AesGcm_Key256_t wrongKey = {0};

    const ByteVector_t testData = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    ByteVector_t encryptedData;

    AesGcm encrypter(key);
    AesGcm decrypter(wrongKey);

    EXPECT_TRUE(encrypter.encrypt(testData, encryptedData));
    EXPECT_NE(testData, encryptedData);

    ByteVector_t plainData;
    EXPECT_TRUE(decrypter.decrypt(encryptedData, plainData));
    EXPECT_NE(testData, plainData);

    EXPECT_TRUE(encrypter.decrypt(encryptedData, plainData));
    CompareVectors(testData, plainData);
}
