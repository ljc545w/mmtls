#include "utility.h"
#include <chrono>
#include <random>

#if !defined(_WIN32)
#include<sys/select.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<netdb.h>
#include<cstring>
#endif

byteArray readU16LenData(BYTE* pBuf, UINT32& refLen) {
	USHORT length = 0;
	byteArray result;
	BYTE* lBuf = pBuf;
	length = (lBuf[0] << 8) | (lBuf[1] << 0);
	refLen = length;
	lBuf += 2;
	if (length > 0) {
		result = byteArray(lBuf, lBuf + length);
	}
	return result;
}

UINT32 writeU16LenData(byteArray& dst, const byteArray& src) {
	USHORT length = (USHORT)src.size();
	dst.push_back((length >> 8) & 0xff);
	dst.push_back((length >> 0) & 0xff);
	for (USHORT i = 0; i < length; i++) {
		dst.push_back(src[i]);
	}
	return (UINT32)length;
}

UINT32 writeU32LenData(byteArray& dst, const byteArray& src) {
	UINT32 length = (UINT32)src.size();
	dst.push_back((length >> 24) & 0xff);
	dst.push_back((length >> 16) & 0xff);
	dst.push_back((length >> 8) & 0xff);
	dst.push_back((length >> 0) & 0xff);
	for (UINT32 i = 0; i < length; i++) {
		dst.push_back(src[i]);
	}
	return length;
}

byteArray getRandom(int n) {
	byteArray key;
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, 255);
	for (int i = 0; i < n; i++) {
		auto randVal = dis(gen);
		key.push_back(randVal & 0xff);
	}
	return key;
}

void xorNonce(byteArray& nonce, UINT32 seq) {
	BYTE* seqBytes = (BYTE*)&seq;
	for (int i = 0; i < 4; i++) {
		size_t pos = nonce.size() - i - 1;
		nonce[pos] ^= seqBytes[i];
	}
}

const std::string getHostByName(const std::string& hostName) {
	std::string host;
	struct addrinfo hints = { 0 };
	struct addrinfo* result = nullptr, * rp = nullptr;
	int s = 0;
	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
	hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
	hints.ai_protocol = 0;          /* Any protocol */
	s = getaddrinfo(hostName.c_str(), nullptr, &hints, &result);
	if (s != 0)
		return "";
	char buf[30] = { 0 };
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		struct sockaddr_in* addr = (struct sockaddr_in*)rp->ai_addr;
		if (inet_ntop(AF_INET, &addr->sin_addr, buf, 30) != nullptr) {
			host = std::string(buf, strlen(buf));
			break;
		}
	}
	freeaddrinfo(result);
	return host;
}