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

#define COMMAND_ADD     "add"
#define COMMAND_EXIT    "exit"
#define COMMAND_EXPORT  "export"
#define COMMAND_FIND    "find"
#define COMMAND_HELP    "help"
#define COMMAND_IMPORT  "import"
#define COMMAND_LOAD    "load"
#define COMMAND_SAVE    "save"
#define COMMAND_VIEW    "view"

static bool MatchCommand(const string& input, const string command, size_t matchIndex = 0)
{
    bool exactMatch = input == command;
    bool letterMatch = false;

    if ((input.size() == 1U) && (command.size() > matchIndex))
    {
        letterMatch = input[0] == command[matchIndex];
    }

    return exactMatch || letterMatch;
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

static StringVector_t GetArgs(string s, string delimiter)
{
    size_t start = 0, end, delimLength = delimiter.length();
    string token;
    StringVector_t res;

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

static bool TryRunCommand(PasswordManager& manager, string command, StringVector_t& args, bool& exit)
{
    if (MatchCommand(command, COMMAND_EXIT, 1))
    {
        SERVICES_RunSavePasswords(manager);
        exit = true;
    }
    else if (MatchCommand(command, COMMAND_SAVE))
    {
        SERVICES_RunSavePasswords(manager);
    }
    else if (MatchCommand(command, COMMAND_ADD))
    {
        SERVICES_RunAddPassword(manager);
    }
    else if (MatchCommand(command, COMMAND_FIND))
    {
        SERVICES_RunFindPassword(manager, args);
    }
    else if (MatchCommand(command, COMMAND_VIEW))
    {
        SERVICES_RunViewPasswords(manager, args);
    }
    else if (MatchCommand(command, COMMAND_LOAD))
    {
        SERVICES_RunLoadPasswords(manager, args);
    }
    else if (MatchCommand(command, COMMAND_EXPORT))
    {
        SERVICES_RunExportPasswords(manager, args);
    }
    else if (MatchCommand(command, COMMAND_IMPORT))
    {
        SERVICES_RunImportPasswords(manager, args);
    }
    else if (MatchCommand(command, COMMAND_HELP))
    {
        DisplayHelp();
    }
    else
    {
        return false;
    }
    return true;
}

void CLI_RunCli(passwords::PasswordManager& manager, StringVector_t args)
{
    bool exit = false;
    string input = "";
    string command = "";

    if (!args.empty())
    {
        string command = args[0];
        TryRunCommand(manager, command, args, exit);
    }

    while (!exit)
    {
        cout << CLI_HEADER;
        getline(cin, input);
        StringVector_t args = GetArgs(input, CLI_ARG_DELIM);
        if (args.size() == 0)
        {
            PrintError(CLI_ERROR_MESSAGE(input));
            continue;
        }

        string command = args[0];
        bool success = TryRunCommand(manager, command, args, exit);
        if (!success)
        {
            PrintError(CLI_ERROR_MESSAGE(input));
        }
    }
}
