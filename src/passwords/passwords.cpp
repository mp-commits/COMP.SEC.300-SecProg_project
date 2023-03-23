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

void PasswordManager::RemoveLogin(const std::string& guid)
{
    for (size_t i = 0; i < m_logins.size(); i++)
    {
        if (m_logins[i].GetGuid() == guid)
        {
            m_logins.erase(m_logins.begin() + i);
            break;
        }
    }
}
