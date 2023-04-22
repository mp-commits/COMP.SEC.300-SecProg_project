/**
 * @file managerservices.hpp
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-03-23
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef MANAGER_SERVICES_HPP
#define MANAGER_SERVICES_HPP

#include "passwords/passwords.hpp"
#include "stringvector.hpp"

extern void SERVICES_RunLoadPasswords(passwords::PasswordManager& manager, StringVector_t args = {});
extern void SERVICES_RunSavePasswords(passwords::PasswordManager& manager, StringVector_t args = {});
extern void SERVICES_RunAddPassword(passwords::PasswordManager& manager, StringVector_t args = {});
extern void SERVICES_RunFindPassword(passwords::PasswordManager& manager, StringVector_t args = {});
extern void SERVICES_RunViewPasswords(passwords::PasswordManager& manager, StringVector_t args = {});
extern void SERVICES_RunImportPasswords(passwords::PasswordManager& manager, StringVector_t args = {});
extern void SERVICES_RunExportPasswords(passwords::PasswordManager& manager, StringVector_t args = {});
extern void SERVICES_RunCopyPassword(passwords::PasswordManager& manager, StringVector_t args = {});

#endif
