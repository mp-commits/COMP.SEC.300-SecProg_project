# COMP.SEC.300-SecProg_project
Project work for the course COMP.SEC.300-2022-2023-1 Secure Programming

For detailed documentation see report.pdf!

## Requirements

- CMake 3.11 or newer. Tested with version 3.20
- Ninja build
- OpenSSL 3.0. Tested with 3.0.4 (Linux) and 3.0.8 (Windows). See build instructions.
- Git installed such that git is available command in PATH.
- Internet connection. CMake needs to fetch libraries from GitHub.

## Building on Ubuntu/Pop-OS

### OpenSSL
Tested with OpenSSL v3.0.4

```
sudo apt install libssl-dev
```

### Build

Tested with GCC 11.3.0 and 12.1.0

```
mkdir build
cd build
cmake -G "Ninja" ..
ninja
```

## Building on Windows

### OpenSSL
Install OpenSSL version 3.0.8: https://slproweb.com/products/Win32OpenSSL.html
OpenSSL must be installed to C:\Program Files\OpenSSL-Win64\

Add C:\Program Files\OpenSSL-Win64\bin to PATH

Set environment variable OPENSSL_CONF=C:\Program
Files\OpenSSL-Win64\bin\openssl.cfg

### Build

Tested with GCC 11.2.0 x86_64-w64-mingw32

```
mkdir build
cd build
cmake -G "Ninja" ..
ninja
```

## Known Issues

- Clipboard library was not confirmed to work on Pop-OS: Copy command may not work.

## Supported commands:
```
add, a : Add a password to the manager. Usage:
    add 

copy, c : Copy a password to clipboard. Usage:
    copy [idx]

save, s : Save passwords to an encrypted file. Usage:     
    save [password]
    save [file] [password]

exit, x : Exit the program. Usage:
    exit 

export, e : Export passwords to a csv file. Usage:        
    export [file]

import, i : Import passwords from a csv file. Usage:      
    import [file]

load, l : Load passwords from an encrypted file. Usage:   
    load [password]
    load [file] [password]

remove, r : Removes password with a specific index. Usage:
    remove [idx]

view, v : View existing passwords. Usage:
    view
    view [page]
    view [idx from] [idx to]

find, f : Find a passwords by string. Usage:
    find [search key]

help, h : Display help. Usage:
    help
    help [cmd]
```
