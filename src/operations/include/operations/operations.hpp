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

extern void OPERATIONS_RunLoadPasswords(passwords::PasswordManager& manager);
extern void OPERATIONS_RunSavePasswords(passwords::PasswordManager& manager);
extern void OPERATIONS_RunAddPassword(passwords::PasswordManager& manager);
extern void OPERATIONS_RunFindPassword(passwords::PasswordManager& manager);

#endif
