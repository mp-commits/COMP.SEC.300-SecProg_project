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

using namespace passwords;
using namespace std;

void SERVICES_RunAddPassword(passwords::PasswordManager& manager, std::ostream& output, std::istream& input, StringVector_t args)
{
    string name = "";
    string domain = "";
    string password = "";

    output << PROMPT_STR_NAME;
    getline(input, name);

    output << PROMPT_STR_DOMAIN;
    getline(input, domain);

    output << PROMPT_STR_PASSWORD;
    getline(input, password);

    if (name.empty() && domain.empty())
    {
        output << ERROR_STR_EMPTY_ID << endl;
        return;
    }

    if (password.empty())
    {
        output << ERROR_STR_EMPTY_PASSWORD << endl;
        return;
    }

    Login_t login(domain, name, password);
    if (manager.AddLogin(login))
    {
        manager.SetDataSaved(false);
    }
}
