/**
 * @file view.cpp
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-03-24
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include "services/managerservices.hpp"
#include "project_definitions.hpp"
#include <iomanip>

using namespace passwords;
using namespace std;

#define DISPLAY_PAGE_SIZE   (10U)

#define IDX_WIDTH           (4)
#define USER_WIDTH          (40)
#define PASSWORD_WIDTH      (20)
#define URL_DISPLAY_WIDTH   (30)

static void PrintLogin(const size_t idx, const Login& login, ostream& output)
{
    output << setw(IDX_WIDTH) << to_string(idx) << " | ";
    output << setw(USER_WIDTH) << login.username << " | ";
    output << setw(PASSWORD_WIDTH) << login.password << " | ";

    if (login.url.size() > URL_DISPLAY_WIDTH)
    {
        output << login.url.substr(0U ,URL_DISPLAY_WIDTH) << "...";
    }
    else
    {
        output << login.url;
    }

    output << endl;
}

static bool MatchToLogin(const string& key, const Login_t& login)
{
    bool urlMatch = login.url.find(key) != string::npos;
    bool nameMatch = login.username.find(key) != string::npos;
    
    return urlMatch || nameMatch;
}

void SERVICES_RunViewPasswords(passwords::PasswordManager& manager, std::ostream& output, std::istream&, StringVector_t args)
{
    const size_t count = manager.Count();

    if (count == 0)
    {
        output << "No login information loaded" << endl;
    }
    else
    {
        try {
            size_t startIdx = 0;
            size_t endIdx = 0;

            if (args.size() == 1U)
            {
                startIdx = 0U;
                endIdx = count;
            }
            else if (args.size() == 2U)
            {
                size_t page = stoi(args[1]);
                startIdx = page * DISPLAY_PAGE_SIZE;
                endIdx = startIdx + DISPLAY_PAGE_SIZE;
            }
            else if (args.size() == 3U)
            {
                startIdx = stoi(args[1]);
                endIdx = stoi(args[2]) + 1U;
            }
            else
            {
                throw std::invalid_argument(ERR_STR_ARG);
            }

            if (startIdx < count)
            {
                for (size_t i = startIdx; (i < count) && (i < endIdx); i++)
                {
                    PrintLogin(i, manager[i], output);
                }
            }
            else
            {
                output << ERR_STR_IDX << endl;
            }
        }
        catch (...)
        {
            output << ERR_STR_ARG << endl;
        }
    }
}

void SERVICES_RunFindPassword(passwords::PasswordManager& manager, std::ostream& output, std::istream&, StringVector_t args)
{
    try
    {
        if (args.size() == 2U)
        {
            for (size_t i = 0; i < manager.Count(); i++)
            {
                Login_t login = manager[i];
                if (MatchToLogin(args[1], login))
                {
                    PrintLogin(i, login, output);
                }
            }
        }
        else
        {
            throw std::invalid_argument(ERR_STR_ARG);
        }
    }
    catch (...)
    {
        output << ERR_STR_ARG << endl;
    }
}

void SERVICES_RunRemovePassword(passwords::PasswordManager& manager, std::ostream& output, std::istream&, StringVector_t args)
{
    const size_t count = manager.Count();

    try {
        if (args.size() == 2U)
        {
            const size_t idx = stoi(args[1]);
            
            if (idx < count)
            {
                if (manager.RemoveLogin(idx))
                {
                    manager.SetDataSaved(false);
                    output << "Removed login number " << idx << endl;
                }
            }
            else
            {
                throw std::invalid_argument(ERR_STR_IDX);
            }
        }
        else
        {
            throw std::invalid_argument(ERR_STR_ARG);
        }
    }
    catch (...)
    {
        output << ERR_STR_ARG << endl;
    }
}
