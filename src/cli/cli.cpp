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

#define COMMAND_ADD  "add"
#define COMMAND_EXIT "exit"
#define COMMAND_FIND "find"
#define COMMAND_HELP "help"
#define COMMAND_LOAD "load"
#define COMMAND_SAVE "save"
#define COMMAND_VIEW "view"

static bool MatchCommand(const string& input, const string command)
{
    if (input.size() == 1U)
    {
        return input[0] == command[0];
    }
    else
    {
        return input == command;
    }
}

static void DisplayHelp()
{
    cout << "Commands:" << endl;
    cout << COMMAND_ADD << endl;
    cout << COMMAND_EXIT << endl;
    cout << COMMAND_FIND << endl;
    cout << COMMAND_HELP << endl;
    cout << COMMAND_LOAD << endl;
    cout << COMMAND_SAVE << endl;
    cout << COMMAND_VIEW << endl;
}

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

        if (MatchCommand(command, COMMAND_EXIT))
        {
            OPERATIONS_RunSavePasswords(manager);
            exit = true;
        }
        else if (MatchCommand(command, COMMAND_SAVE))
        {
            OPERATIONS_RunSavePasswords(manager);
        }
        else if (MatchCommand(command, COMMAND_ADD))
        {
            OPERATIONS_RunAddPassword(manager);
        }
        else if (MatchCommand(command, COMMAND_FIND))
        {
            OPERATIONS_RunFindPassword(manager, args);
        }
        else if (MatchCommand(command, COMMAND_VIEW))
        {
            OPERATIONS_RunViewPasswords(manager, args);
        }
        else if (MatchCommand(command, COMMAND_LOAD))
        {
            OPERATIONS_RunLoadPasswords(manager, args);
        }
        else if (MatchCommand(command, COMMAND_HELP))
        {
            DisplayHelp();
        }
        else
        {
            PrintError(CLI_ERROR_MESSAGE(input));
        }
    }
}
