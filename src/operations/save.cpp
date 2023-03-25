/**
 * @file save.cpp
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-03-23
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include "operations/operations.hpp"
#include "cryptfile/cryptfile.hpp"

#include <fstream>
#include <iostream>

using namespace encryption;
using namespace fileops;
using namespace passwords;

void OPERATIONS_RunSavePasswords(passwords::PasswordManager& manager, OperationArgs_t args)
{
    const std::string FILENAME = "crypt.cont";
    const AESGCM_Key256_t TEST_KEY = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10};

    std::fstream inputFile(FILENAME, std::ios_base::binary | std::ios_base::trunc);

    if (inputFile.good())
    {
        std::cout << "Saving to '" << FILENAME << "'" << std::endl;
        CryptFile crypt(TEST_KEY, inputFile);
        crypt.Save(manager);
    }
    else
    {
        std::cout << "Failed to save to '" << FILENAME << "'" << std::endl;
    }
}
