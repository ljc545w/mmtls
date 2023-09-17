#pragma once
#ifndef __MMTLS_CONST__
#define __MMTLS_CONST__
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include "custom_defs.h"
#if !defined(_WIN32)
#include <cstring>
#endif
#include <string>

constexpr uint16 ProtocolVersion = 0xF104;
constexpr uint16 TLS_PSK_WITH_AES_128_GCM_SHA256 = 0xA8;
constexpr uint8 MagicAbort = 0x15;
constexpr uint8 MagicHandshake = 0x16;
constexpr uint8 MagicRecord = 0x17;
constexpr uint8 MagicSystem = 0x19;

constexpr uint32 TCP_NoopRequest = 0x6;
constexpr uint32 TCP_NoopResponse = 0x3B9ACA06;
constexpr int ServerEcdhCurve = NID_X9_62_prime256v1;
constexpr char ServerEcdhX[] = "1da177b6a5ed34dabb3f2b047697ca8bbeb78c68389ced43317a298d77316d54";
constexpr char ServerEcdhY[] = "4175c032bc573d5ce4b3ac0b7f2b9a8d48ca4b990ce2fa3ce75cc9d12720fa35";
extern EC_GROUP* curve;
extern EC_KEY* ServerEcdh;

inline std::string bytesFromHex(const std::string& _Src) {
	std::string _Out;
	for (unsigned int i = 0; i < _Src.length(); i += 2) {
		_Out.push_back(std::stoi(_Src.substr(i, 2), 0, 16));
	}
	return _Out;
}

inline std::string toHexString(const std::string& _Src) {
	std::string _dst;
	char tmp[4] = { 0 };
	for (unsigned int i = 0; i < _Src.length(); i++) {
		memset(tmp, 0, 4);
		unsigned char b = _Src[i];
#if defined(_WIN32)
		sprintf_s(tmp, "%02X", b);
#else
		sprintf(tmp, "%02X", b);
#endif
		_dst += std::string(tmp, 2);
	}
	return _dst;
}

constexpr uint32 AEAD_TAG_LEN = 16;
#endif