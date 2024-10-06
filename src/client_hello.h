#pragma once
#include "custom_defs.h"
#include "session_ticket.h"
#include <openssl/ecdsa.h>

struct clientHelloTag {
	uint16 protocolVersion = 0;
	uint16Array cipherSuites;
	byteArray random;
	UINT32 timestamp;
	std::map<uint16, std::vector<byteArray>> extensions;
};

class clientHello : public clientHelloTag {
public:
#if OPENSSL_API_LEVEL < 30000
	static clientHello newECDHEHello(const EC_KEY* cliPubKey, const EC_KEY* cliVerKey);
	static clientHello newPskOneHello(const EC_KEY* cliPubKey, const EC_KEY* cliVerKey, sessionTicket& ticket);
#else
	static clientHello newECDHEHello(const EVP_PKEY* cliPubKey, const EVP_PKEY* cliVerKey);
	static clientHello newPskOneHello(const EVP_PKEY* cliPubKey, const EVP_PKEY* cliVerKey, sessionTicket& ticket);
#endif
	static clientHello newPskZeroHello(sessionTicket& ticket);
	byteArray serialize();
};