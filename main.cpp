/**
 * @file main.cpp
 * @author Mikael Penttinen
 * @brief 
 * @version 0.1
 * @date 2023-03-14
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include <iostream>
#include <string>
#include "cli/cli.hpp"
#include "passwords/passwords.hpp"
#include "stringvector.hpp"

using std::string;
using std::cout;
using passwords::PasswordManager;

static PasswordManager f_manager;

int main(int argc, char* argv[])
{
    StringVector_t args;
    for (int i = 1; i < argc; i++)
    {
        args.push_back(std::string(argv[i]));
    }

    CLI_RunCli(f_manager, args);
    return 0;
}
