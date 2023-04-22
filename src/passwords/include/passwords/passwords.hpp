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

namespace util
{
extern bool StringIsValid(const std::string& str);
}

typedef struct Login {
    Login() = default;

    Login(std::string url,
        std::string username,
        std::string password) :
    url(url),
    username(username),
    password(password) {}

    ~Login() {}

    bool operator==(const Login& rhs)
    {
        return (url == rhs.url)
                && (username == rhs.username)
                && (password == rhs.password);
    }

    std::string url;
    std::string username;
    std::string password;
} Login_t;

class PasswordManager {
public:
    PasswordManager() : m_logins({}), m_dataSaved(true) {} 
    ~PasswordManager() {}

    bool RemoveLogin(const size_t idx);

    bool AddLogin(const Login_t& login);


    size_t Count() const
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

    const std::vector<Login_t>& GetLoginVector() const
    {
        return m_logins;
    }

    std::vector<Login_t>& GetLoginVector()
    {
        return m_logins;
    }

    void SetDataSaved(bool set)
    {
        m_dataSaved = set;
    }

    bool GetDataSaved()
    {
        return m_dataSaved;
    }

private:
    bool Exists(const Login_t& login);
    bool LoginIsValid(const Login_t& login);

    std::vector<Login_t> m_logins;
    bool m_dataSaved;
};

} // namespace passwords
#endif
