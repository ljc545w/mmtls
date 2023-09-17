#pragma once
#include <openssl/ecdsa.h>
#include "custom_defs.h"

struct serverHelloTag {
	uint16 protocolVersion = 0;
	uint16 cipherSuites = 0;
	EC_KEY* publicKey = nullptr;
};

class serverHello : public serverHelloTag {
public:
	static serverHello readServerHello(const byteArray& buf, int& err);
};