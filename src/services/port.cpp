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
#include <cstring>
#include <cerrno>

using namespace passwords;
using namespace std;

static bool FileExists(const string& filename)
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

static void RunAddLogins(const vector<Login_t>& logins, PasswordManager& manager, ostream& output)
{
    size_t ok = 0, fail = 0;
    for (auto l: logins)
    {
        manager.AddLogin(l) ? ok++ : fail++;
    }

    output << "Parsed " << logins.size() << " logins, " << ok << " added, " << fail << " rejected." << endl;
}

extern void SERVICES_RunImportPasswords(passwords::PasswordManager& manager, ostream& output, istream& input, StringVector_t args)
{
    string filename;
    
    if (args.size() == 2)
    {
        filename = args[1];
    }
    else
    {
        output << ERR_STR_ARG << endl;
        return;
    }

    ifstream file(filename, ios::in);
    
    if (!file.good())
    {
        output << ERR_STR_FILE_OPEN(filename) << ": " << strerror(errno) << endl;
    }
    else
    {
        try
        {
            vector<Login_t> newLogins;
            if (csv::CSV_GetLoginsFromFile(file, newLogins))
            {
                RunAddLogins(newLogins, manager, output);
            }
            else
            {
                throw runtime_error(ERR_STR_FILE);
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
    }

    file.close();
}

extern void SERVICES_RunExportPasswords(passwords::PasswordManager& manager, ostream& output, istream& input, StringVector_t args)
{
    string filename;

    if (args.size() == 2)
    {
        filename = args[1];
    }
    else
    {
        output << ERR_STR_ARG << endl;
        return;
    }

    if (FileExists(filename))
    {
        output << ERR_STR_FILE_EXISTS(filename) << endl;
        return;
    }
    
    ofstream file(filename, ios::out | ios::trunc);
    
    if (!file.good())
    {
        output << ERR_STR_FILE_OPEN(filename) << "': " << strerror(errno) << endl;
    }
    else
    {
        try
        {
            output << PROMPT_STR_WRITING_FILE(filename) << endl;
            csv::CSV_SetLoginsToFile(file, manager.GetLoginVector());
        }
        catch(exception& ex)
        {
            output << ex.what() << endl;
        }
        catch(...)
        {
            output << ERR_STR_GENERIC << endl;
        }
    }

    file.close();
}
