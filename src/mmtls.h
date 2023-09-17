#pragma once
#include "custom_defs.h"
#include "session.h"
#include "client_hello.h"
#include "server_hello.h"
#include "record.h"
#include "handshakeHasher.h"
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#if defined(_WIN32)
#include <ws2tcpip.h>
#else

#endif
#include <atomic>

void InitServerEcdh();
void UnInitServerEcdh();

struct MMTLSClientTag {
	SOCKET conn = NULL;
	std::atomic<INT32> status = 0;
	EC_KEY* publicEcdh = nullptr;
	EC_KEY* verifyEcdh = nullptr;
	EC_KEY* serverEcdh = nullptr;
	HandshakeHasher* handshakeHasher = nullptr;
	UINT32 serverSeqNum = 0;
	UINT32 clientSeqNum = 0;
	Session* session = nullptr;
};

class MMTLSClient : public MMTLSClientTag {
public:
	MMTLSClient();
	~MMTLSClient();
	int HandShake(const std::string& host);
	int Noop();
	int Close();
	int reset();
	bool handshakeComplete();
	int sendClientHello(clientHello& hello);
	int readServerHello(serverHello& hello);
	int readSignature(trafficKeyPair& trafficKey);
	int readNewSessionTicket(const byteArray& comKey, const trafficKeyPair& trafficKey);
	int readServerFinish(const byteArray& comKey, const trafficKeyPair& trafficKey);
	int sendClientFinish(const byteArray& comKey, const trafficKeyPair& trafficKey);
	int sendNoop();
	int readNoop();
	int readRecord(mmtlsRecord& record);
	byteArray computeEphemeralSecret(const EC_POINT* serverPublicKey, const BIGNUM* publicEcdhPrivateKey);
	int computeTrafficKey(const byteArray& shareKey, const byteArray& info, trafficKeyPair& pair);
	bool verifyEcdsa(const byteArray& data);
	byteArray hkdfExpand(const std::string& prefix, HandshakeHasher* const hash);
	byteArray hmac(const byteArray& k, const byteArray& d);
	int genKeyPairs();
private:
	bool m_bIsNewSession = false;
};