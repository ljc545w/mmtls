#pragma once
#include "session.h"
#include "custom_defs.h"
#include "record.h"
#include "mmtls_openssl.h"
#include <atomic>
#include "handshakeHasher.h"

struct MMTLSClientShortTag {
	SOCKET conn = NULL;
	std::atomic<INT32> status = 0;
	BYTE* packetReader = nullptr;
	HandshakeHasher* handshakeHasher = nullptr;
	uint32 serverSeqNum = 0;
	uint32 clientSeqNum = 0;
	Session* session = nullptr;
};

class MMTLSClientShort : public MMTLSClientShortTag {
public:
	MMTLSClientShort();
	~MMTLSClientShort();
	int Request(const std::string& host, const std::string& path, const byteArray& req, byteArray& resp);
	int Close();
	int packHttp(const std::string& host, const std::string& path, const byteArray& req, byteArray& resp);
	int genDataPart(const std::string& host, const std::string& path, const byteArray& req, byteArray& resp);
	int buildRequestHeader(const std::string& host, int length, byteArray& resp);
	int parseResponse(SOCKET conn, byteArray& resp);
	int readServerHello();
	int readServerFinish();
	int readDataRecord(mmtlsRecord& record);
	int readAbort();
	int earlyDataKey(const byteArray& pskAccess, const sessionTicket& ticket, trafficKeyPair& pair);
	int computeTrafficKey(const byteArray& shareKey, const byteArray& info, trafficKeyPair& pair);
	byteArray hkdfExpand(const std::string& prefix, const HandshakeHasher* hash);
	byteArray hmac(const byteArray& k, const byteArray& d);
private:
	BYTE* packetReaderEnd = nullptr;
	std::string szRespHeader;
};