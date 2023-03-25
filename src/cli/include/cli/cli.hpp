/**
 * @file cli.hpp
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-03-23
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef CLI_HPP
#define CLI_HPP

#include "passwords/passwords.hpp"
#include "stringvector.hpp"

extern void CLI_RunCli(passwords::PasswordManager& manager, StringVector_t args = {});

#endif // CLI_HPP
