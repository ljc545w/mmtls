#pragma once
#include "mmtls_openssl.h"
#include "custom_defs.h"

struct serverHelloTag {
	uint16 protocolVersion = 0;
	uint16 cipherSuite = 0;
	byteArray random;
	UINT32 timestamp;
	std::map<uint16, std::vector<byteArray>> extensions;
};

class serverHello : public serverHelloTag {
public:
	static serverHello readServerHello(const byteArray& buf, int& err);
};