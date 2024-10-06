#pragma once
#include <openssl/ecdsa.h>
#include "custom_defs.h"

struct serverHelloTag {
	uint16 protocolVersion = 0;
	uint16 cipherSuites = 0;
#if OPENSSL_API_LEVEL < 30000
	EC_KEY* publicKey = nullptr;
#else
	EVP_PKEY* publicKey = nullptr;
#endif
};

class serverHello : public serverHelloTag {
public:
	static serverHello readServerHello(const byteArray& buf, int& err);
};