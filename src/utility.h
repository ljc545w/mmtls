#pragma once
#include "custom_defs.h"

#ifndef OPENSSL_API_LEVEL
#include <openssl/macros.h>
#endif

#if OPENSSL_API_LEVEL >= 30000
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/evp.h>
#endif

byteArray getRandom(int n);
void xorNonce(byteArray& nonce, UINT32 seq);
byteArray readU16LenData(BYTE* pBuf, UINT32& refLen);
UINT32 writeU16LenData(byteArray& dst, const byteArray& src);
UINT32 writeU32LenData(byteArray& dst, const byteArray& src);
const std::string getHostByName(const std::string& hostName);

#if OPENSSL_API_LEVEL >= 30000
int EVP_EC_KEY_oct2key(EVP_PKEY* key, const unsigned char* buf, size_t len);
int EVP_EC_KEY_key2buf(const EVP_PKEY* key, std::string& outData);
int EVP_EC_KEY_get0_public_key(const EC_GROUP* curve, const EVP_PKEY* key, EC_POINT** ppEcPoint);
int EVP_EC_KEY_get0_private_key(const EVP_PKEY* key, BIGNUM** ppBigNum);
#endif