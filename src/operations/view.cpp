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

#include "operations/operations.hpp"
#include <iostream>
#include <iomanip>

using namespace passwords;
using namespace std;

#define MAX_DISPLAY_COUNT (15U)

#define DOMAIN_WIDTH (20)
#define USER_WIDTH (10)
#define PASSWORD_WIDTH (10)

static void PrintLogin(const Login& login)
{
    cout << login.GetUrl() << setw(DOMAIN_WIDTH) << " ";
    cout << login.GetUsername() << setw(USER_WIDTH) << " ";
    cout << login.GetPassword() << setw(PASSWORD_WIDTH) << " ";
    cout << endl;
}

void OPERATIONS_RunViewPasswords(passwords::PasswordManager& manager, OperationArgs_t args)
{
    Login header("URL", "USERNAME", "PASSWORD");
    PrintLogin(header);

    for (size_t i = 0; i < manager.Count(); i++)
    {
        PrintLogin(manager[i]);
    }
}
