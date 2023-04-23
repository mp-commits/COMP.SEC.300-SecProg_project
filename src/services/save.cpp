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

#include "services/managerservices.hpp"
#include "cryptfile/cryptfile.hpp"
#include "encryption/util.hpp"
#include "encryption/sha256.hpp"
#include "project_definitions.hpp"
#include "services/saltidservice.hpp"

#include <fstream>
#include <iostream>
#include <cstring>
#include <cerrno>

using namespace encryption;
using namespace encryptionUtil;
using namespace fileops;
using namespace passwords;
using namespace std;

static bool CheckFileCanBeWritten(string filename)
{
    bool allowWrite = false;
    ifstream file(filename, std::ios::in | std::ios::ate | std::ios::binary);

    if (file)
    {
        const size_t fileSize = file.tellg();
        
        if (fileSize >= (PROJECT_ID_HEADER_SIZE + PROJECT_SALT_SIZE))
        {
            file.seekg(0);
            ByteVector_t header(PROJECT_ID_HEADER_SIZE);
            ByteVector_t salt(PROJECT_SALT_SIZE);

            file.read((char*)header.data(), PROJECT_ID_HEADER_SIZE);
            file.read((char*)salt.data(), PROJECT_SALT_SIZE);

            if (IDSERVICE_IsApplicationHeader(header) && IDSERVICE_IsRegistered(salt))
            {
                // This file has previously been loaded to the manager. Allow overwrite
                allowWrite = true;
                cout << "File '" << filename << "' already exists and has been loaded previously. Overwriting!" << endl;
            }
            else if (IDSERVICE_IsApplicationHeader(header))
            {
                cout << "WARNING: Container '" << filename << "' already exists and has not been loaded previously!" << endl;
                cout << "Confirm overwrite (yes): ";

                string input;
                getline(cin, input);

                if (input == "yes")
                {
                    allowWrite = true;
                }
            }
            else
            {
                // File does not have the correct header. Do not allow writing to it in any case.
            }
        }

        // File does not have the correct content. Do not allow writing to it in any case.
    }
    else
    {
        // File doesn't exist
        allowWrite = true;
    }

    file.close();
    return allowWrite;
}

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
        cout << PROMPT_STR_FILE_ENTRY_DEFAULT;
        getline(cin, filename);
        
        if (filename.empty())
        {
            filename = DEFAULT_FILE_NAME;
        }

        cout << PROMPT_STR_PASSWORD;
        getline(cin, password);
    }

    if (CheckFileCanBeWritten(filename))
    {
        std::ofstream outputFile(filename, std::ios_base::trunc | std::ios_base::out | std::ios_base::binary);

        if (outputFile.good())
        {
            string errStr;
            std::cout << PROMPT_STR_WRITING_FILE(filename) << std::endl;
            CryptFile crypt(password);
            crypt.Save(outputFile, manager.GetLoginVector(), errStr);
            outputFile.close();

            manager.SetDataSaved(true);
        }
        else
        {
            std::cout << ERR_STR_FILE_OPEN(filename) << std::strerror(errno) << std::endl;
        }
    }
    else
    {
        cout << ERR_STR_FILE << endl;
    }

}
