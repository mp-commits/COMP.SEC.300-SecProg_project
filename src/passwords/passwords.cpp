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
