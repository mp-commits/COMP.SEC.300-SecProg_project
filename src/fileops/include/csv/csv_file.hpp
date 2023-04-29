/**
 * @file csv_file.hpp
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-04-28
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef CSV_FILE_HPP
#define CSV_FILE_HPP

#include <istream>
#include <ostream>
#include "passwords/passwords.hpp"

namespace csv {

extern bool CSV_GetLoginsFromFile(std::istream& file, std::vector<passwords::Login_t>& logins);

extern bool CSV_SetLoginsToFile(std::ostream& file, const std::vector<passwords::Login_t>& logins);

} // namespace csv

#endif // CSV_FILE_HPP
