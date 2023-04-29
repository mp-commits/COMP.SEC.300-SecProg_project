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
#include <cstring>
#include <cerrno>

using namespace encryption;
using namespace encryptionUtil;
using namespace fileops;
using namespace passwords;
using namespace std;

#define FILE_PROMPT "Enter input filename (empty for default): "
#define DEFAULT_FILE_NAME "manager_container.crypt"

static void RunAddLogins(const vector<Login_t>& logins, PasswordManager& manager, ostream& output)
{
    size_t ok = 0, fail = 0;
    for (auto l: logins)
    {
        manager.AddLogin(l) ? ok++ : fail++;
    }

    output << "Parsed " << logins.size() << " logins, " << ok << " added, " << fail << " rejected." << endl;
}

void SERVICES_RunLoadPasswords(passwords::PasswordManager& manager, ostream& output, istream&, StringVector_t args)
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
        output << ERR_STR_ARG << endl;
        return;
    }

    ifstream inputFile(filename, ios_base::in | ios_base::binary);

    if (inputFile.good())
    {
        try
        {
            CryptFile crypt(password);
            vector<Login_t> logins;

            if(!crypt.Load(inputFile, logins))
            {
                throw runtime_error("Failed decryption");
            }

            RunAddLogins(logins, manager, output);
        }
        catch(exception& ex)
        {
            output << ex.what() << endl;
        }
        catch(...)
        {
            output << current_exception().__cxa_exception_type()->name() << endl;
        }
    }
    else
    {
        output << ERR_STR_FILE_OPEN(filename) << "': " << strerror(errno) << endl;
    }

    inputFile.close();
}
