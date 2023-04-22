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
#include <iostream>
#include <iomanip>

using namespace passwords;
using namespace std;

#define DISPLAY_PAGE_SIZE   (10U)

#define IDX_WIDTH           (4)
#define USER_WIDTH          (40)
#define PASSWORD_WIDTH      (20)
#define URL_DISPLAY_WIDTH   (30)

static void PrintLogin(const size_t idx, const Login& login)
{
    cout << setw(IDX_WIDTH) << to_string(idx) << " | ";
    cout << setw(USER_WIDTH) << login.username << " | ";
    cout << setw(PASSWORD_WIDTH) << login.password << " | ";

    if (login.url.size() > URL_DISPLAY_WIDTH)
    {
        cout << login.url.substr(0U ,URL_DISPLAY_WIDTH) << "...";
    }
    else
    {
        cout << login.url;
    }

    cout << endl;
}

static bool MatchToLogin(const string& key, const Login_t& login)
{
    bool urlMatch = login.url.find(key) != string::npos;
    bool nameMatch = login.username.find(key) != string::npos;
    
    return urlMatch || nameMatch;
}

void SERVICES_RunViewPasswords(passwords::PasswordManager& manager, StringVector_t args)
{
    const size_t count = manager.Count();

    if (args.size() > 1U)
    {
        try {
            size_t startIdx;
            size_t endIdx;

            if (args.size() == 2U)
            {
                size_t page = stoi(args[1]);
                startIdx = page * DISPLAY_PAGE_SIZE;
                endIdx = startIdx + DISPLAY_PAGE_SIZE;
            }
            else if (args.size() > 2U)
            {
                startIdx = stoi(args[1]);
                endIdx = stoi(args[2]) + 1U;
            }

            if (startIdx < count)
            {
                for (size_t i = startIdx; (i < count) && (i < endIdx); i++)
                {
                    PrintLogin(i, manager[i]);
                }
            }
        }
        catch (...)
        {
            cout << "Invalid argument: " << args[1] << endl;
        }
    }
    else
    {
        for (size_t i = 0; i < count; i++)
        {
            PrintLogin(i, manager[i]);
        }
    }
}

void SERVICES_RunFindPassword(passwords::PasswordManager& manager, StringVector_t args)
{
    if (args.size() == 2U)
    {
        for (size_t i = 0; i < manager.Count(); i++)
        {
            Login_t login = manager[i];
            if (MatchToLogin(args[1], login))
            {
                PrintLogin(i, login);
            }
        }
    }
    else
    {
        cout << "Invalid arguments!" << endl;
    }
}

void SERVICES_RunRemovePassword(passwords::PasswordManager& manager, StringVector_t args)
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
                    cout << "Removed login number " << idx << endl;
                }
            }
            else
            {
                throw std::invalid_argument("Index too high!");
            }
        }
        else
        {
            throw std::invalid_argument("Wrong number of arguments!");
        }
    }
    catch (...)
    {
        cout << "Invalid arguments" << endl;
    }
}
