/**
 * @file util.hpp
 * @author Mikael Penttinen (mikael.penttinen@tuni.fi)
 * @brief 
 * @version 0.1
 * @date 2023-03-18
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef ENCRYPTION_UTIL_HPP
#define ENCRYPTION_UTIL_HPP

#include "bytevector.hpp"

namespace encryptionUtil
{

inline std::string vectorToString(const ByteVector_t& data_in)
{
    return std::string(data_in.begin(), data_in.end());
}

inline ByteVector_t StringToVector(const std::string& string_in)
{
    return ByteVector_t(string_in.begin(), string_in.end());
}

}

#endif
