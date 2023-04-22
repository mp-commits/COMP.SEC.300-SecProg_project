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

#define FILE_PROMPT "Enter file name (empty for default): "
#define PASSWORD_PROMPT "Enter file password: "
#define DEFAULT_FILE_NAME "manager_container.crypt"

void SERVICES_RunSavePasswords(passwords::PasswordManager& manager, StringVector_t args)
{
    string filename = DEFAULT_FILE_NAME;
    string password;

    if (args.size() == 2U)
    {
        password = args[1];
    }
    else if (args.size() == 3U)
    {
        filename = args[1];
        password = args[2];
    }
    else
    {
        cout << FILE_PROMPT;
        getline(cin, filename);
        
        if (filename.empty())
        {
            filename = DEFAULT_FILE_NAME;
        }

        cout << PASSWORD_PROMPT;
        getline(cin, password);
    }

    std::ofstream outputFile(filename, std::ios_base::trunc | std::ios_base::out);

    if (outputFile.good())
    {
        string errStr;
        std::cout << "Saving to '" << filename << "'" << std::endl;
        CryptFile crypt(password);
        crypt.Save(outputFile, manager.GetLoginVector(), errStr);
        outputFile.close();
    }
    else
    {
        std::cout << "Failed to save to '" << filename << "': " << std::strerror(errno) << std::endl;
    }
}
