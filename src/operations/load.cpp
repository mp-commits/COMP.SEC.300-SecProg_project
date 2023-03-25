/**
 * @file load.cpp
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

void OPERATIONS_RunLoadPasswords(passwords::PasswordManager& manager, OperationArgs_t args)
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

    std::ifstream inputFile(fileName, std::ios_base::in);

    if (inputFile.good())
    {
        string errStr;
        std::cout << "Loading from '" << fileName << "'" << std::endl;
        CryptFile crypt(key);
        if(!crypt.Load(inputFile, manager, errStr))
        {
            std::cout << errStr << std::endl;
        }
        inputFile.close();
    }
    else
    {
        std::cout << "Failed to open '" << fileName << "': " << std::strerror(errno) << std::endl;
    }
}
