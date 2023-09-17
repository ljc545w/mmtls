#pragma once
#include "session_ticket.h"

struct trafficKeyPairTag {
	byteArray clientKey;
	byteArray serverKey;
	byteArray clientNonce;
	byteArray serverNonce;
};

class trafficKeyPair : public trafficKeyPairTag {
};

struct SessionTag {
	newSessionTicket tk;
	byteArray pskAccess;
	byteArray pskRefresh;
	trafficKeyPair appKey;
};

class Session : public SessionTag {
public:
	Session() {};
	Session(const newSessionTicket& tickets, const byteArray& pskAccess, const byteArray& pskRefresh);
	bool Save(const std::string& path);
	static int loadSession(const std::string& path, Session& s);
};