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

#include "services/idservice.hpp"
#include "project_definitions.hpp"
#include <algorithm>

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

const ByteVector_t IDSERVICE_GetApplicationHeader()
{
    return PROJECT_FILE_ID_HEADER;
}

bool IDSERVICE_IsApplicationHeader(const ByteVector_t& id)
{
    return id == IDSERVICE_GetApplicationHeader();
}
