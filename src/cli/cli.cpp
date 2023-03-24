/**
 * @file cli.cpp
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-03-23
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include "cli/cli.hpp"
#include "operations/operations.hpp"
#include <iostream>
#include <string>

using namespace passwords;
using namespace std;

#define CLI_HEADER "manager: "
#define CLI_ARG_DELIM " "
#define CLI_ERROR_MESSAGE(line) ("Invalid input: '" + line + "'")

#define COMMAND_ADD "add"
#define COMMAND_EXIT "exit"
#define COMMAND_FIND "find"
#define COMMAND_LOAD "load"
#define COMMAND_SAVE "save"

static OperationArgs_t GetArgs(string s, string delimiter)
{
    size_t start = 0, end, delimLength = delimiter.length();
    string token;
    OperationArgs_t res;

    while ((end = s.find(delimiter, start)) != string::npos)
    {
        token = s.substr(start, end - start);
        start = end + delimLength;
        res.push_back(token);
    }

    res.push_back(s.substr(start));
    return res;
}

static void PrintError(string msg)
{
    cout << msg << endl;
}

void CLI_RunCli(passwords::PasswordManager& manager)
{
    bool exit = false;
    string input = "";
    string command = "";

    while (!exit)
    {
        cout << CLI_HEADER;
        getline(cin, input);
        OperationArgs_t args = GetArgs(input, CLI_ARG_DELIM);
        if (args.size() == 0)
        {
            PrintError(CLI_ERROR_MESSAGE(input));
            continue;
        }

        string command = args[0];

        if (command == COMMAND_EXIT)
        {
            OPERATIONS_RunSavePasswords(manager);
            exit = true;
        }
        else if (command == COMMAND_SAVE)
        {
            OPERATIONS_RunSavePasswords(manager);
        }
        else if (command == COMMAND_ADD)
        {
            OPERATIONS_RunAddPassword(manager);
        }
        else if (command == COMMAND_FIND)
        {
            OPERATIONS_RunFindPassword(manager, args);
        }
        else
        {
            PrintError(CLI_ERROR_MESSAGE(input));
        }
    }
}
