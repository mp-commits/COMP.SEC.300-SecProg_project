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

#include "services/managerservices.hpp"
#include "cryptfile/cryptfile.hpp"
#include "encryption/util.hpp"
#include "encryption/sha256.hpp"
#include "project_definitions.hpp"

#include <fstream>
#include <iostream>
#include <cstring>
#include <cerrno>

using namespace encryption;
using namespace encryptionUtil;
using namespace fileops;
using namespace passwords;
using namespace std;

#define FILE_PROMPT "Enter input filename (empty for default): "
#define DEFAULT_FILE_NAME "manager_container.crypt"

static void RunAddLogins(const vector<Login_t>& logins, PasswordManager& manager)
{
    size_t ok = 0, fail = 0;
    for (auto l: logins)
    {
        manager.AddLogin(l) ? ok++ : fail++;
    }

    cout << "Parsed " << logins.size() << " logins, " << ok << " added, " << fail << " rejected." << endl;
}

void SERVICES_RunLoadPasswords(passwords::PasswordManager& manager, StringVector_t args)
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
        cout << PROMPT_STR_PASSWORD;
        getline(cin, password);
    }

    std::ifstream inputFile(filename, std::ios_base::in | std::ios_base::binary);

    if (inputFile.good())
    {
        try
        {
            string errStr;
            CryptFile crypt(password);
            std::vector<passwords::Login_t> logins;

            if(!crypt.Load(inputFile, logins, errStr))
            {
                std::cout << errStr << std::endl;
            }

            RunAddLogins(logins, manager);
        }
        catch(...)
        {
            std::cout << ERR_STR_GENERIC << std::endl;
        }
    }
    else
    {
        std::cout << ERR_STR_FILE_OPEN(filename) << "': " << std::strerror(errno) << std::endl;
    }

    inputFile.close();
}
