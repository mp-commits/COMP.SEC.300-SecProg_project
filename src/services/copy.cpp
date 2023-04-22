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
#include "clip.h"
#include "project_definitions.hpp"

#include <iostream>

using namespace passwords;
using namespace std;

void SERVICES_RunCopyPassword(passwords::PasswordManager& manager, StringVector_t args)
{
    if (args.size() == 2U)
    {
        try
        {
            size_t idx = stoi(args[1]);

            if (idx < manager.Count())
            {
                Login_t login = manager[idx];
                if (clip::set_text(login.password))
                {
                    cout << "Successfully copied: " << login.password << endl;
                }
                else
                {
                    cout << "Failed to copy!" << endl;
                }
            }
            else
            {
                cout << ERR_STR_IDX << endl;
            }
        }
        catch (...)
        {
            cout << ERR_STR_GERENIC << endl;
        }
    }
    else
    {
        cout << ERR_STR_ARG << endl;
    }
}
