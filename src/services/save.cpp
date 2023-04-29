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
#include "services/idservice.hpp"

#include <fstream>
#include <cstring>
#include <cerrno>

using namespace encryption;
using namespace encryptionUtil;
using namespace fileops;
using namespace passwords;
using namespace std;

static bool CheckFileCanBeWritten(string filename, ostream& output, istream& input)
{
    bool allowWrite = false;
    ifstream file(filename, ios::in | ios::ate | ios::binary);

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
                output << "File '" << filename << "' already exists and has been loaded previously. Overwriting!" << endl;
            }
            else if (IDSERVICE_IsApplicationHeader(header))
            {
                output << "WARNING: Container '" << filename << "' already exists and has not been loaded previously!" << endl;
                output << "Confirm overwrite (yes): ";

                string inputStr;
                getline(input, inputStr);

                if (inputStr == "yes")
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

void SERVICES_RunSavePasswords(passwords::PasswordManager& manager, ostream& output, istream& input, StringVector_t args)
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
        output << ERR_STR_ARG << endl;
        return;
    }

    if (CheckFileCanBeWritten(filename, output, input))
    {
        ofstream outputFile(filename, ios_base::trunc | ios_base::out | ios_base::binary);

        try
        {
            if (outputFile.good())
            {
                output << PROMPT_STR_WRITING_FILE(filename) << endl;
                CryptFile crypt(password);

                if (crypt.Save(outputFile, manager.GetLoginVector()))
                {
                    manager.SetDataSaved(true);
                }
            }
            else
            {
                output << ERR_STR_FILE_OPEN(filename) << strerror(errno) << endl;
            }
        }
        catch(exception& ex)
        {
            output << ex.what() << endl;
        }
        catch(...)
        {
            output << current_exception().__cxa_exception_type()->name() << endl;
        }

        outputFile.close();
    }
    else
    {
        output << ERR_STR_FILE << endl;
    }

}
