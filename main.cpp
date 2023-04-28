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

#include <csignal>
#include <iostream>
#include <string>
#include "cli/cli.hpp"
#include "passwords/passwords.hpp"
#include "stringvector.hpp"
#include "version.hpp"

#define ARGUMENT_VERSION "--version"

using std::string;
using passwords::PasswordManager;

static PasswordManager f_manager;

extern "C"
{
    extern const char* GIT_TAG;
    extern const char* GIT_REV;
    extern const char* GIT_BRANCH;
}

void ExitSignalHandler( int signum )
{
    std::cout << "Exiting..." << std::endl;
    exit(signum);  
}

void DisplayVersion(void)
{
    string tag(GIT_TAG);

    if (tag.empty())
    {
        std::cout << "Password manager: " << "development build: " << __DATE__ << " " << __TIME__ << std::endl; 
    }
    else
    {
        std::cout << "Manager: " << "release " << GIT_TAG << std::endl; 
    }

    std::cout << "Version: " << VERSION_NUMBER_MAJOR << 
                    "." << VERSION_NUMBER_MINOR << 
                    " " << GIT_BRANCH << "-" << GIT_REV <<
                    " " << VERSION_NAME_STR << std::endl;
}

int main(int argc, char* argv[])
{
    try
    {
        signal(SIGINT, ExitSignalHandler);

        StringVector_t args;
        for (int i = 1; i < argc; i++)
        {
            args.push_back(std::string(argv[i]));
        }

        if (!args.empty() && ((args[0] == ARGUMENT_VERSION)))
        {
            DisplayVersion();
        }
        else
        {
            CLI_RunCli(f_manager, args);
        }

        return 0;
    }
    catch (...)
    {
        return 1;
    }
}
