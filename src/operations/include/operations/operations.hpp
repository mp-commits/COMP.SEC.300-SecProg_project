/**
 * @file operations.hpp
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-03-23
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef OPERATIONS_HPP
#define OPERATIONS_HPP

#include "passwords/passwords.hpp"
#include <string>
#include <vector>

typedef std::vector<std::string> OperationArgs_t;

extern void OPERATIONS_RunLoadPasswords(passwords::PasswordManager& manager, OperationArgs_t args = {});
extern void OPERATIONS_RunSavePasswords(passwords::PasswordManager& manager, OperationArgs_t args = {});
extern void OPERATIONS_RunAddPassword(passwords::PasswordManager& manager, OperationArgs_t args = {});
extern void OPERATIONS_RunFindPassword(passwords::PasswordManager& manager, OperationArgs_t args = {});

#endif
