/**
 * @file saltidservice.hpp
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-04-22
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SALT_ID_SERVICE_HPP
#define SALT_ID_SERVICE_HPP

#include "bytevector.hpp"

extern void IDSERVICE_AddId(const ByteVector_t& id);

extern bool IDSERVICE_IsRegistered(const ByteVector_t& id);

extern const ByteVector_t IDSERVICE_GetApplicationHeader();

extern bool IDSERVICE_IsApplicationHeader(const ByteVector_t& id);

#endif // SALT_ID_SERVICE_HPP