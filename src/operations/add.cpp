/**
 * @file add.cpp
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-03-23
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include "operations/operations.hpp"
#include <iostream>

using namespace passwords;
using namespace std;

#define PROMPT_NAME "Name: "
#define PROMPT_DOMAIN "Domain: "
#define PROMPT_PASSWORD "Password: "

#define ERROR_EMPTY_PASSWORD "Password cannot be empty"
#define ERROR_EMPTY_ID "Both name and domain cannot be empty"

void OPERATIONS_RunAddPassword(passwords::PasswordManager& manager, OperationArgs_t args)
{
    string name = "";
    string domain = "";
    string password = "";

    cout << PROMPT_NAME;
    getline(cin, name);

    cout << PROMPT_DOMAIN;
    getline(cin, domain);

    cout << PROMPT_PASSWORD;
    getline(cin, password);

    if (name.empty() && domain.empty())
    {
        cout << ERROR_EMPTY_ID << endl;
        return;
    }

    if (password.empty())
    {
        cout << ERROR_EMPTY_PASSWORD << endl;
        return;
    }

    Login login(domain, name, password);
    manager.AddLogin(login);
}
