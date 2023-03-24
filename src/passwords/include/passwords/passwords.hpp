/**
 * @file passwords.hpp
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-03-23
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef PASSWORDS_HPP
#define PASSWORDS_HPP

#include <stdint.h>
#include <string>
#include <vector>

namespace passwords {

class Login {
public:
    Login(std::string url,
          std::string username,
          std::string password,
          std::string guid) :
    m_url(url),
    m_username(username),
    m_password(password),
    m_guid(guid){}

    ~Login() {}

    std::string GetUrl() 
    {
        return m_url;
    }

    std::string GetUsername() 
    {
        return m_username;
    }

    std::string GetPassword() 
    {
        return m_password;
    }

    std::string GetGuid() 
    {
        return m_guid;
    }

    void SetUrl(const std::string& val) noexcept 
    {
        m_url = val;
    }

    void SetUsername(const std::string& val) noexcept 
    {
        m_username = val;
    }

    void SetPassword(const std::string& val) noexcept 
    {
        m_password = val;
    }

    void SetGuid(const std::string& val) noexcept 
    {
        m_guid = val;
    }

    bool operator==(const Login& rhs)
    {
        return m_guid == rhs.m_guid;
    }

private:
    std::string m_url;
    std::string m_username;
    std::string m_password;
    std::string m_guid;
};

class PasswordManager {
public:
    PasswordManager() : m_logins({}) {} 
    ~PasswordManager() {}

    void RemoveLogin(const std::string& guid);

    void AddLogin(const Login& login) 
    {
        m_logins.push_back(login);
    }

    size_t Count() 
    {
        return m_logins.size();
    }

    void Clear() 
    {
        m_logins.clear();
    }

    Login& operator[](int index)
    {
        return m_logins[index];
    }

private:
    std::vector<Login> m_logins;
};

} // namespace passwords
#endif
