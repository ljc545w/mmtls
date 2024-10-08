#pragma once
#ifndef __MMTLS_OPENSSL_H__
#define __MMTLS_OPENSSL_H__ 1
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x3000000fL
#include <openssl/macros.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#else
#ifndef OPENSSL_API_LEVEL
#define OPENSSL_API_LEVEL 0
#endif // OPENSSL_API_LEVEL
#endif // OPENSSL_VERSION_NUMBER >= 0x3000000fL

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/tls1.h>
#include <openssl/ecdh.h>
#include <openssl/kdf.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>

#if (OPENSSL_API_LEVEL >= 30000 && !defined(OPENSSL3))
#ifndef NO_USE_OPENSSL3
#define OPENSSL3
#else
#pragma warning(disable:4996) // deprecated apis
#endif // NO_USE_OPENSSL3
#endif // (OPENSSL_API_LEVEL >= 30000 && !defined(OPENSSL3))

#endif // __MMTLS_OPENSSL_H__