# COMP.SEC.300-SecProg_project
Project work for the course COMP.SEC.300-2022-2023-1 Secure Programming

## Building on Ubuntu/Pop-OS

### OpenSSL
```
sudo apt install libssl-dev
```

### Build

Tested with OpenSSL v3.0.4, GCC 12.2, CMake 3.20

```
mkdir build
cd build
cmake ..
```

## Building on Windows

### OpenSSL
Install OpenSSL version 3.0.8: https://slproweb.com/products/Win32OpenSSL.html
OpenSSL must be installed to C:\Program Files\OpenSSL-Win64\

Add C:\Program Files\OpenSSL-Win64\bin to PATH

Set environment variable OPENSSL_CONF=C:\Program
Files\OpenSSL-Win64\bin\openssl.cfg

### Build

tested with GCC 11.2.0 x86_64-w64-mingw32

```
mkdir build
cd build
cmake ..
```

## Known Issues

- Clipboard library was not confirmed to work on Pop-OS: Copy command may not work.
