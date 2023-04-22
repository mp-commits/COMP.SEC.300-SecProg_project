/**
 * @file saltidservice.cpp
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-04-22
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include "services/saltidservice.hpp"
#include "project_definitions.hpp"
#include <algorithm>

constexpr uint8_t APPLICATION_HEADER[PROJECT_ID_HEADER_SIZE] = 
{
    0x5d, 0x6a, 0x13, 0x0e, 0x7a, 0xd2, 0x71, 0xf7, 
    0x45, 0x18, 0x1f, 0xb9, 0x82, 0x96, 0x18, 0x67, 
    0x28, 0x4d, 0x57, 0x72, 0x43, 0xa7, 0x84, 0x9d, 
    0x1b, 0x7c, 0x8b, 0x87, 0x9d, 0x95, 0xc9, 0x22
};

static std::vector<ByteVector_t> f_storage;

void IDSERVICE_AddId(const ByteVector_t& id)
{
    if (!IDSERVICE_IsRegistered(id))
    {
        f_storage.push_back(id);
    }
}

bool IDSERVICE_IsRegistered(const ByteVector_t& id)
{
    auto it = std::find(f_storage.begin(), f_storage.end(), id);
    
    if (it != f_storage.end())
    {
        return true;
    }
    
    return false;
}

const ByteVector_t& IDSERVICE_GetApplicationHeader()
{
    static const ByteVector_t vec(APPLICATION_HEADER, APPLICATION_HEADER + PROJECT_ID_HEADER_SIZE);
    return vec;
}

bool IDSERVICE_IsApplicationHeader(const ByteVector_t& id)
{
    return id == IDSERVICE_GetApplicationHeader();
}
