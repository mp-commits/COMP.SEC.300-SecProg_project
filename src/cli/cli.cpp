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
#include "services/managerservices.hpp"
#include <iostream>
#include <iomanip>
#include <string>
#include <functional>

using namespace passwords;
using namespace std;

#define CLI_HEADER "manager: "
#define CLI_ARG_DELIM " "
#define CLI_ERROR_MESSAGE(line) ("Invalid input: '" + line + "'")

#define COMMAND_ADD     "add"
#define COMMAND_COPY    "copy"
#define COMMAND_EXIT    "exit"
#define COMMAND_EXPORT  "export"
#define COMMAND_FIND    "find"
#define COMMAND_HELP    "help"
#define COMMAND_IMPORT  "import"
#define COMMAND_LOAD    "load"
#define COMMAND_REMOVE  "remove"
#define COMMAND_SAVE    "save"
#define COMMAND_VIEW    "view"

static bool MatchCommand(const string& input, const string command, size_t matchIndex);
static void DisplayHelp(PasswordManager&, std::ostream& output, std::istream& input, StringVector_t args);
static StringVector_t GetArgs(string s, string delimiter);
static void PrintError(string msg);
static bool TryRunCommand(PasswordManager& manager, string command, StringVector_t& args, bool& exit);

typedef struct 
{
    size_t letterAccessIdx;
    const string cmd;
    function<void(passwords::PasswordManager&, std::ostream& output, std::istream& input, StringVector_t)> func;
    const string description;
    const StringVector_t params;
} CommandDescription_t;

static const CommandDescription_t COMMANDS[] = {
    {0U, COMMAND_ADD,       SERVICES_RunAddPassword,        "Add a password to the manager",            {""}},
    {0U, COMMAND_COPY,      SERVICES_RunCopyPassword,       "Copy a password to clipboard",             {"[idx]"}},
    {0U, COMMAND_SAVE,      SERVICES_RunSavePasswords,      "Save passwords to an encrypted file",      {"[password]", "[file] [password]"}},
    {1U, COMMAND_EXIT,      nullptr,                        "Exit the program",                         {""}},
    {0U, COMMAND_EXPORT,    SERVICES_RunExportPasswords,    "Export passwords to a csv file",           {"[file]"}},
    {0U, COMMAND_IMPORT,    SERVICES_RunImportPasswords,    "Import passwords from a csv file",         {"[file]"}},
    {0U, COMMAND_LOAD,      SERVICES_RunLoadPasswords,      "Load passwords from an encrypted file",    {"[password]", "[file] [password]"}},
    {0U, COMMAND_REMOVE,    SERVICES_RunRemovePassword,     "Removes password with a specific index",   {"[idx]"}},
    {0U, COMMAND_VIEW,      SERVICES_RunViewPasswords,      "View existing passwords",                  {"", "[page]", "[idx from] [idx to]"}},
    {0U, COMMAND_FIND,      SERVICES_RunFindPassword,       "Find a passwords by string",               {"[search key]"}},
    {0U, COMMAND_HELP,      DisplayHelp,                    "Display help",                             {"", "[cmd]"}}
};

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

static void DisplayHelp(PasswordManager&, std::ostream& output, std::istream&, StringVector_t args)
{
    string cmd = "";
    if (args.size() > 1)
    {
        cmd = args[1];
    }
    else
    {
        output << "To view specific command run 'help [comamnd]'" << endl;
        output << "Supported commands:" << endl;
    }

    for (auto c: COMMANDS)
    {
        if ((cmd == "") || MatchCommand(cmd, c.cmd, c.letterAccessIdx))
        {
            output << c.cmd << ", " << c.cmd[c.letterAccessIdx] << " : " << c.description << ". Usage:" << endl;
            for (auto param : c.params)
            {
                output << "    " << c.cmd << " " << param << endl;
            }
            output << endl;
        }
    }
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
        if (!token.empty())
        {
            res.push_back(token);
        }
    }

    token = s.substr(start);
    if (!token.empty())
    {
        res.push_back(token);
    }

    return res;
}

static void ValidateArgs(StringVector_t& vec)
{
    const std::string allowedCharacters = "abcdefghijklmnopqrstuvwxyzäöåABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÅ0123456789()_-,.*/\\:;";

    for (auto& s: vec)
    {
        for (auto c: s)
        {
            if (allowedCharacters.find(c) == std::string::npos)
            {
                vec.clear();
                return;
            }
        }
    }
}

static void PrintError(string msg)
{
    cout << msg << endl;
}

static bool TryRunCommand(PasswordManager& manager, string command, StringVector_t& args, bool& exit)
{
    static bool unsavedPrompted = false;
    bool success = true;

    try
    {
        if (MatchCommand(command, COMMAND_EXIT, 1))
        {
            // Check for exit command first
            if (!manager.GetDataSaved() && !unsavedPrompted)
            {
                PrintError("Unsaved data in the manager. Consider running save service.");
                unsavedPrompted = true;
            }
            else
            {
                exit = true;
            }
        }
        else
        {
            // Check for all other commands
            success = false;

            for (auto c: COMMANDS)
            {
                if (MatchCommand(command, c.cmd, c.letterAccessIdx))
                {
                    c.func(manager, cout, cin, args);

                    success = true;
                    break;
                }
            }
        }
    }
    catch(...)
    {
        success = false;
    }

    return success;
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
        ValidateArgs(args);

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
