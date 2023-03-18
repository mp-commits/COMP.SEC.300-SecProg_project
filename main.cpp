/**
 * @file main.cpp
 * @author Mikael Penttinen
 * @brief 
 * @version 0.1
 * @date 2023-03-14
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include <iostream>
#include <string>
#include "encryption/encryption.hpp"

using std::string;
using std::cout;

int main(int argc, char* argv[])
{
    const string plaintext = "Hello beautiful world. This is a good day to be encrypted.";

    cout << plaintext << std::endl;

    encryption::AesGcm_Key128_t key128 = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};
    encryption::AesGcm crypter128(key128);

    string ciphertext = crypter128.encryptString(plaintext);
    cout << std::hex << ciphertext << std::endl;
    string decrypted = crypter128.decryptString(ciphertext);
    cout << decrypted << std::endl;

    encryption::AesGcm_Key256_t key256 = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                                       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    encryption::AesGcm crypter256(key256);

    ciphertext = crypter256.encryptString(plaintext);
    cout << std::hex << ciphertext << std::endl;
    decrypted = crypter256.decryptString(ciphertext);
    cout << decrypted << std::endl;

    return 0;
}
