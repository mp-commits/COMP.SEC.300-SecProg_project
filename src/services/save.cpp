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

#define FILE_PROMPT "Enter file name (empty for default): "
#define PASSWORD_PROMPT "Enter file password: "
#define DEFAULT_FILE_NAME "manager_container.crypt"

static bool CheckFileCanBeWritten(string filename)
{
    bool allowWrite = false;
    ifstream file(filename, std::ios::in | std::ios::ate);

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
        cout << FILE_PROMPT;
        getline(cin, filename);
        
        if (filename.empty())
        {
            filename = DEFAULT_FILE_NAME;
        }

        cout << PASSWORD_PROMPT;
        getline(cin, password);
    }

    if (CheckFileCanBeWritten(filename))
    {
        std::ofstream outputFile(filename, std::ios_base::trunc | std::ios_base::out);

        if (outputFile.good())
        {
            string errStr;
            std::cout << "Saving to '" << filename << "'" << std::endl;
            CryptFile crypt(password);
            crypt.Save(outputFile, manager.GetLoginVector(), errStr);
            outputFile.close();

            manager.SetDataSaved(true);
        }
        else
        {
            std::cout << "Failed to save to '" << filename << "': " << std::strerror(errno) << std::endl;
        }
    }
    else
    {
        cout << "Invalid or illegal file. No data written!" << endl;
    }

}
