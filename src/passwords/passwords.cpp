/**
 * @file passwords.cpp
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-03-23
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include "passwords/passwords.hpp"

using namespace passwords;

bool passwords::util::StringIsValid(const std::string& str)
{
    const std::string allowedCharacters = " abcdefghijklmnopqrstuvwxyzäöåABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÅ0123456789!@#$%^&*()_-+=[]{};:,.<>?/~";

    for (auto c: str)
    {
        if (allowedCharacters.find(c) == std::string::npos)
        {
            return false;
        }
    }

    return true;
}

bool PasswordManager::RemoveLogin(const size_t idx)
{
    if (idx < m_logins.size())
    {
        m_logins.erase(m_logins.begin() + idx);
        return true;
    }

    return false;
}

bool PasswordManager::AddLogin(const Login_t& login)
{
    if (LoginIsValid(login) && !Exists(login))
    {
        m_logins.push_back(login);
        return true;
    }
    return false;
}

bool PasswordManager::Exists(const Login_t& login)
{
    for (auto l: m_logins)
    {
        if (l == login)
        {
            return true;
        }
    }
    return false;
}

bool PasswordManager::LoginIsValid(const Login_t& login)
{
    if (login.password.empty() || (login.url.empty() && login.username.empty()))
    {
        // Password must not be empty!
        // URL and/or username must exit!
        return false;
    }

    bool valid = util::StringIsValid(login.password);

    if (valid && !login.url.empty())
    {
        valid &= util::StringIsValid(login.url);
    }
    if (valid && !login.username.empty())
    {
        valid &= util::StringIsValid(login.username);
    }

    return valid;
}
