/**
 * @file sha256.hpp
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-03-25
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SHA256_HPP
#define SHA256_HPP

#include <string>
#include "bytevector.hpp"

#define SHA256_SIZE (32U)

namespace encryption
{

extern ByteVector_t CalculateSHA256(const ByteVector_t& data);

} // encryption

#endif // SHA256_HPP
