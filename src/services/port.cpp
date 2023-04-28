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
#include "project_definitions.hpp"
#include "csv/csv_file.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <cstring>
#include <cerrno>
#include <map>

using namespace passwords;
using namespace std;

static bool FileExists(const std::string& filename)
{
    bool exists = false;
    ifstream file(filename);

    if (file)
    {
        exists = true;
    }

    file.close();
    return exists;
}

static void RunAddLogins(const vector<Login_t>& logins, PasswordManager& manager)
{
    size_t ok = 0, fail = 0;
    for (auto l: logins)
    {
        manager.AddLogin(l) ? ok++ : fail++;
    }

    cout << "Parsed " << logins.size() << " logins, " << ok << " added, " << fail << " rejected." << endl;
}

extern void SERVICES_RunImportPasswords(passwords::PasswordManager& manager, StringVector_t args)
{
    string filename;
    
    if (args.size() < 2)
    {
        cout << PROMPT_STR_FILE_ENTRY;
        getline(cin, filename);
    }
    else
    {
        filename = args[1];
    }

    ifstream file(filename, std::ios::in);
    
    if (!file.good())
    {
        std::cout << ERR_STR_FILE_OPEN(filename) << ": " << std::strerror(errno) << std::endl;
    }
    else
    {
        try
        {
            vector<Login_t> newLogins;
            if (csv::CSV_GetLoginsFromFile(file, newLogins))
            {
                RunAddLogins(newLogins, manager);
            }
            else
            {
                throw std::runtime_error(ERR_STR_FILE);
            }

        }
        catch(std::exception& ex)
        {
            std::cout << ex.what() << std::endl;
        }
        catch(...)
        {
            std::cout << current_exception().__cxa_exception_type()->name() << std::endl;
        }
    }

    file.close();
}

extern void SERVICES_RunExportPasswords(passwords::PasswordManager& manager, StringVector_t args)
{
    string filename;

    if (args.size() < 2)
    {
        cout << PROMPT_STR_FILE_ENTRY;
        getline(cin, filename);
    }
    else
    {
        filename = args[1];
    }

    if (FileExists(filename))
    {
        std::cout << ERR_STR_FILE_EXISTS(filename) << std::endl;
        return;
    }
    
    ofstream file(filename, std::ios::out | std::ios::trunc);
    
    if (!file.good())
    {
        std::cout << ERR_STR_FILE_OPEN(filename) << "': " << std::strerror(errno) << std::endl;
    }
    else
    {
        try
        {
            cout << PROMPT_STR_WRITING_FILE(filename) << std::endl;
            csv::CSV_SetLoginsToFile(file, manager.GetLoginVector());
        }
        catch(std::exception& ex)
        {
            std::cout << ex.what() << std::endl;
        }
        catch(...)
        {
            std::cout << ERR_STR_GENERIC << std::endl;
        }
    }

    file.close();
}
