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

#include "services/managerservices.hpp"
#include "project_definitions.hpp"
#include <iostream>

using namespace passwords;
using namespace std;

void SERVICES_RunAddPassword(passwords::PasswordManager& manager, StringVector_t args)
{
    string name = "";
    string domain = "";
    string password = "";

    cout << PROMPT_STR_NAME;
    getline(cin, name);

    cout << PROMPT_STR_DOMAIN;
    getline(cin, domain);

    cout << PROMPT_STR_PASSWORD;
    getline(cin, password);

    if (name.empty() && domain.empty())
    {
        cout << ERROR_STR_EMPTY_ID << endl;
        return;
    }

    if (password.empty())
    {
        cout << ERROR_STR_EMPTY_PASSWORD << endl;
        return;
    }

    Login_t login(domain, name, password);
    if (manager.AddLogin(login))
    {
        manager.SetDataSaved(false);
    }
}
