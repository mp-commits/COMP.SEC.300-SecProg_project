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

#define FILE_PROMPT "Entern input filename (empty for default): "
#define PASSWORD_PROMPT "Enter file password: "
#define DEFAULT_FILE_NAME "manager_container.crypt"

static void RunAddLogins(const vector<Login_t>& logins, PasswordManager& manager)
{
    size_t ok = 0, fail = 0;
    for (auto l: logins)
    {
        if (manager.AddLogin(l))
        {
            ok++;
        }
        else
        {
            fail++;
        }
    }

    cout << "Parsed " << logins.size() << " logins, " << ok << " added, " << fail << " duplicates." << endl;
}

void OPERATIONS_RunLoadPasswords(passwords::PasswordManager& manager, StringVector_t args)
{
    string password;
    string filename = DEFAULT_FILE_NAME;

    if (args.size() == 2)
    {
        password = args[1];
    }
    else if (args.size() == 3)
    {
        filename = args[1];
        password = args[2];
    }
    else
    {
        string newFile;
        cout << FILE_PROMPT;
        getline(cin, newFile);
        if (!newFile.empty())
        {
            filename = newFile;
        }
        cout << PASSWORD_PROMPT;
        getline(cin, password);
    }

    ByteVector_t keySha = CalculateSHA256(StringToVector(password));
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

    std::ifstream inputFile(filename, std::ios_base::in);

    if (inputFile.good())
    {
        string errStr;
        std::cout << "Loading from '" << filename << "'" << std::endl;
        CryptFile crypt(key);
        std::vector<passwords::Login_t> logins;
        if(!crypt.Load(inputFile, logins, errStr))
        {
            std::cout << errStr << std::endl;
        }
        inputFile.close();
        RunAddLogins(logins, manager);
    }
    else
    {
        std::cout << "Failed to open '" << filename << "': " << std::strerror(errno) << std::endl;
    }
}
