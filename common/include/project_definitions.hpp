/**
 * @file project_definitions.hpp
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-04-22
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef PROJECT_DEFINITIONS_HPP
#define PROJECT_DEFINITIONS_HPP

#define DEFAULT_FILE_NAME "manager_container.crypt"

#define PROJECT_ID_HEADER_SIZE  (32U)    // Bytes
#define PROJECT_SALT_SIZE       (32U)    // Bytes

#define ERR_STR_GERENIC     "Something went wrong!"
#define ERR_STR_ARG         "Invalid argument!"
#define ERR_STR_CMD         "Invalid command!"
#define ERR_STR_IDX         "Invalid index!"
#define ERR_STR_FILE        "Invalid file!"
#define ERR_STR_CHECKSUM    "Invalid checksum!"
#define ERR_STR_DECRYPT     "Decryption failed!"

#define ERROR_STR_EMPTY_PASSWORD        "Password cannot be empty"
#define ERROR_STR_EMPTY_ID              "Both name and domain cannot be empty"
#define ERROR_STR_INCOMPATIBLE_FILE     "File is not compatible with this program"

#define ERR_STR_FILE_EXISTS(name_string)    ("File already exists: " + (name_string))
#define ERR_STR_FILE_OPEN(name_string)      ("Failed to open: " + (name_string))

#define PROMPT_STR_PASSWORD     "Enter password: "
#define PROMPT_STR_FILE_ENTRY   "Enter filename: "
#define PROMPT_STR_NAME         "Enter name: "
#define PROMPT_STR_DOMAIN       "Enter domain: "

#define PROMPT_STR_FILE_ENTRY_DEFAULT           "Enter filename (empty for default): "
#define PROMPT_STR_WRITING_FILE(name_string)    ("Wiring to file " + (name_string))

#define KEY_STR_URL         "url"
#define KEY_STR_USERNAME    "username"
#define KEY_STR_PASSWORD    "password"


#endif //PROJECT_DEFINITIONS_HPP