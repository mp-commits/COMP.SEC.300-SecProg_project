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
#include "encryption/util.hpp"
#include "encryption/sha256.hpp"

#include <fstream>
#include <iostream>
#include <cstring>
#include <cerrno>

using namespace encryption;
using namespace encryptionUtil;
using namespace fileops;
using namespace passwords;
using namespace std;

#define PASSWORD_PROMPT "Enter file password: "
#define DEFAULT_FILE_NAME "manager_container.crypt"

void OPERATIONS_RunSavePasswords(passwords::PasswordManager& manager, OperationArgs_t args)
{
    cout << PASSWORD_PROMPT;
    string input;
    getline(cin, input);

    ByteVector_t keySha = CalculateSHA256(StringToVector(input));
    AESGCM_Key256_t key;
    
    if (keySha.size() == key.size())
    {
        for (size_t i = 0; i < key.size(); i++)
        {
            key[i] = keySha[i];
        }
    }
    else
    {
        return;
    }

    string fileName = DEFAULT_FILE_NAME;
    if (args.size() > 1)
    {
        fileName = args[1];
    }

    std::ofstream outputFile(fileName, std::ios_base::binary | std::ios_base::trunc | std::ios_base::in);

    if (outputFile.good())
    {
        std::cout << "Saving to '" << fileName << "'" << std::endl;
        CryptFile crypt(key);
        crypt.Save(outputFile, manager);
    }
    else
    {
        std::cout << "Failed to save to '" << fileName << "': " << std::strerror(errno) << std::endl;
    }
}
