#pragma once
#if defined(_WIN32)
#include <ws2tcpip.h>
#include<windows.h>
#pragma warning(disable:26495)
#else
#include <string>
#endif
#include<vector>
#include<iostream>
#include<fstream>
#include<map>

#ifndef _WIN32
typedef unsigned char BYTE;
typedef unsigned int UINT32;
typedef unsigned short USHORT;
typedef int INT32;
typedef int SOCKET;
#endif // !_WIN32

#ifndef INVALID_SOCKET
#define INVALID_SOCKET ~0
#endif

#ifndef SOCKET_ERROR
#define SOCKET_ERROR -1
#endif

typedef std::vector<BYTE> byteArray;
typedef unsigned short uint16;
typedef unsigned char uint8;
typedef unsigned int uint32;
typedef std::vector<uint16> uint16Array;