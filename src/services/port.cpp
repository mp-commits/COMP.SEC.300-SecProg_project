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
#include "boost/tokenizer.hpp"
#include "project_definitions.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <cstring>
#include <cerrno>
#include <map>

using namespace passwords;
using namespace std;

typedef std::map<std::string, size_t> KeyMap_t;

#define OUTPUT_HEADER "\"url\",\"username\",\"password\""
#define OUTPUT_SEPARATOR ','

static inline size_t Max3(size_t a, size_t b, size_t c)
{
    size_t temp = (a > b) ? a : b;
    return (temp > c) ? temp : c;
}

static inline void Escape(string& s)
{
    s.insert(s.begin(), '"');
    s.insert(s.end(), '"');
}

static StringVector_t Tokenize(const string& line)
{
    boost::tokenizer<boost::escaped_list_separator<char> > tok(line);
    StringVector_t tokens;

    for(boost::tokenizer<boost::escaped_list_separator<char>>::iterator beg = tok.begin(); beg != tok.end(); ++beg)
    {
        tokens.push_back(*beg);
    }

    return tokens;
}

static KeyMap_t GenerateKeys(const StringVector_t& tokens)
{
    KeyMap_t keys;

    for (size_t i = 0; i < tokens.size(); i++)
    {
        string key = tokens[i];

        // Transform to lowercase just in case
        transform(key.begin(), key.end(), key.begin(), [](unsigned char c){ return std::tolower(c); });
        keys.insert({key, i});
    }

    return keys;
}

static bool KeyExists(const KeyMap_t& map, string key)
{
    if (map.find(key) != map.end())
    {
        return true;
    }
    return false;
}

static bool FileExists(const std::string& filename)
{
    bool exists = false;
    ifstream file(filename);

    if (file)
    {
        exists = true;
    }

    file.close();
    return exists;
}

static void ImportFromFile(ifstream& file, passwords::PasswordManager& manager)
{
    string line;
    KeyMap_t keys;
    bool firstLine = true;

    size_t processed = 0, accepted = 0, failed = 0;

    while (getline(file, line))
    {
        const StringVector_t tokens = Tokenize(line);
        
        if (firstLine)
        {
            keys = GenerateKeys(tokens);
            firstLine = false;

            bool allKeysOk = KeyExists(keys, KEY_STR_URL) && KeyExists(keys, KEY_STR_USERNAME) && KeyExists(keys, KEY_STR_PASSWORD);
            if (!allKeysOk)
            {
                cout << ERR_STR_FILE << endl;
                return;
            }
        }
        else
        {
            const size_t idxUrl = keys[KEY_STR_URL], idxUsername = keys[KEY_STR_USERNAME], idxPassword = keys[KEY_STR_PASSWORD];
            const size_t maxIdx = Max3(idxUrl, idxPassword, idxUsername);
            
            if (tokens.size() > maxIdx)
            {
                Login_t login;
                login.username = tokens[idxUsername];
                login.url = tokens[idxUrl];
                login.password = tokens[idxPassword];

                processed++;
                manager.AddLogin(login) ? accepted++ : failed++;
            }
            else
            {
                cout << "INVALID LINE: " << line << endl;
            }
        }
    }

    if (accepted > 0U)
    {
        manager.SetDataSaved(false);
    }

    cout << "Parsed " << processed << " logins, " << accepted << " imported, " << failed << " duplicates." << endl;
}

static void ExportToFile(ofstream& file, passwords::PasswordManager& manager)
{
    file << OUTPUT_HEADER << endl;

    for (size_t i = 0; i < manager.Count(); i++)
    {
        Login_t login = manager[i];

        Escape(login.url);
        Escape(login.username);
        Escape(login.password);

        file << login.url << OUTPUT_SEPARATOR << login.username << OUTPUT_SEPARATOR << login.password << endl;
    }
}

extern void SERVICES_RunImportPasswords(passwords::PasswordManager& manager, StringVector_t args)
{
    string filename;

    if (args.size() < 2)
    {
        cout << PROMPT_STR_FILE_ENTRY;
        getline(cin, filename);
    }
    else
    {
        filename = args[1];
    }

    ifstream file(filename, std::ios::in);
    
    if (!file.good())
    {
        std::cout << ERR_STR_FILE_OPEN(filename) << ": " << std::strerror(errno) << std::endl;
        return;
    }

    ImportFromFile(file, manager);
    file.close();
}

extern void SERVICES_RunExportPasswords(passwords::PasswordManager& manager, StringVector_t args)
{
    string filename;

    if (args.size() < 2)
    {
        cout << PROMPT_STR_FILE_ENTRY;
        getline(cin, filename);
    }
    else
    {
        filename = args[1];
    }

    if (FileExists(filename))
    {
        std::cout << ERR_STR_FILE_EXISTS(filename) << std::endl;
        return;
    }
    
    ofstream file(filename, std::ios::out | std::ios::trunc);
    
    if (!file.good())
    {
        std::cout << ERR_STR_FILE_OPEN(filename) << "': " << std::strerror(errno) << std::endl;
        file.close();
        return;
    }

    cout << PROMPT_STR_WRITING_FILE(filename) << std::endl;

    ExportToFile(file, manager);

    file.close();
}
