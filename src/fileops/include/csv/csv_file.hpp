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

#include <fstream>
#include "passwords/passwords.hpp"

namespace csv {

extern bool CSV_GetLoginsFromFile(std::ifstream& file, std::vector<passwords::Login_t>& logins);

extern bool CSV_SetLoginsToFile(std::ofstream& file, const std::vector<passwords::Login_t>& logins);

} // namespace csv
