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
    if (!Exists(login))
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