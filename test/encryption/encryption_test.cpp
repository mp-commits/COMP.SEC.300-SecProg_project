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
#include "encryption/sha256.hpp"
#include "encryption/util.hpp"

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

TEST(TEST_SUITE_NAME, deriveWithEmptySalt)
{
    const string password = "SecretKey";
    const ByteVector_t salt = {};
    const ByteVector_t salt2 = {0}; // 0 salt should be the same as {}
    const ByteVector_t salt3 = {1};

    EVPKDF der(password, salt);
    EVPKDF der2(password, salt2);
    EVPKDF der3(password, salt3);

    ENCRYPTION_Key128_t key;
    der.derive128(key);
    ENCRYPTION_Key128_t key2;
    der2.derive128(key2);
    ENCRYPTION_Key128_t key3;
    der3.derive128(key3);

    EXPECT_EQ(key, key2);
    EXPECT_NE(key, key3);
}

TEST(TEST_SUITE_NAME, sha256empty)
{
    const ByteVector_t expected = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };

    auto actual = encryption::CalculateSHA256(encryptionUtil::StringToVector(""));

    EXPECT_EQ(expected, actual);
}

TEST(TEST_SUITE_NAME, sha256basic)
{
    const std::string hello = "HelloWorld";

    const ByteVector_t expected = {
        0x87, 0x2e, 0x4e, 0x50, 0xce, 0x99, 0x90, 0xd8, 
        0xb0, 0x41, 0x33, 0x0c, 0x47, 0xc9, 0xdd, 0xd1,
        0x1b, 0xec, 0x6b, 0x50, 0x3a, 0xe9, 0x38, 0x6a,
        0x99, 0xda, 0x85, 0x84, 0xe9, 0xbb, 0x12, 0xc4
    };

    auto actual = encryption::CalculateSHA256(encryptionUtil::StringToVector(hello));

    EXPECT_EQ(expected, actual);
}

TEST(TEST_SUITE_NAME, sha256invalid)
{
    const std::string hello = "HelloWorld";

    const ByteVector_t expected = {
        0x87, 0x2e, 0x4e, 0x50, 0xce, 0x99, 0x90, 0xd8, 
        0xb0, 0x41, 0x33, 0x0c, 0x47, 0xc9, 0xdd, 0xd1,
        0x1b, 0xec, 0x6b, 0x50, 0x3a, 0xe9, 0x38, 0x6a,
        0x99, 0xda, 0x85, 0x84, 0xe9, 0xbb, 0x12, 0xc4
    };

    auto actual = encryption::CalculateSHA256(encryptionUtil::StringToVector(hello + " "));

    EXPECT_NE(expected, actual);
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
