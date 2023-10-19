#include "mmtls_short.h"
#include "utility.h"
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <algorithm>
#include "signature.h"
#include "server_finish.h"
#include "client_finish.h"
#include "client_hello.h"
#include "const.h"
#include "logger.hpp"

#if !defined(_WIN32)
#include<sys/select.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<netdb.h>
#endif

static byteArray hkdfExpand(const EVP_MD* hasher, const byteArray& preudorandomKey, const byteArray& info, int length)
{
	EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	byteArray result(length, 0);
	size_t outlen = length, ret = 0;
	ret = EVP_PKEY_derive_init(pctx) <= 0
		|| EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0
		|| EVP_PKEY_CTX_set_hkdf_md(pctx, hasher) <= 0
		|| EVP_PKEY_CTX_set1_hkdf_key(pctx, preudorandomKey.data(), (unsigned)preudorandomKey.size()) <= 0
		|| EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), (unsigned)info.size()) <= 0
		|| EVP_PKEY_derive(pctx, result.data(), &outlen) <= 0;
	EVP_PKEY_CTX_free(pctx);
	return result;
}

MMTLSClientShort::MMTLSClientShort() {
	handshakeHasher = new HandshakeHasher(EVP_sha256());
}

MMTLSClientShort::~MMTLSClientShort() {
	if (handshakeHasher)
		delete handshakeHasher;
}

int MMTLSClientShort::Request(const std::string& host, const std::string& path, const byteArray& req, byteArray& resp) {
	LL_INFO("Short link request begin!!!!");
	sockaddr_in serverAddress = { 0 };
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(80);
	const std::string ip = getHostByName(host);
	int rc = 0;
	byteArray httpPacket;
	byteArray response;
	trafficKeyPair trafficKey;
	mmtlsRecord dataRecord;
	packetReader = nullptr;
	packetReaderEnd = nullptr;
	if (session == nullptr) {
		rc = -1;
		goto wrapup;
	}
	if (conn == NULL) {
		// ´´½¨socket
		conn = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (conn == INVALID_SOCKET) {
			rc = -1;
			goto wrapup;
		}
#if defined(_WIN32)
		InetPtonA(AF_INET, ip.c_str(), &serverAddress.sin_addr.s_addr);
#else
		inet_pton(AF_INET, ip.c_str(), &serverAddress.sin_addr.s_addr);
#endif
		if (connect(conn, reinterpret_cast<sockaddr*>(&serverAddress), sizeof(sockaddr)) == SOCKET_ERROR)
		{
			rc = -1;
			goto wrapup;
		}
	}
	rc = packHttp(host, path, req, httpPacket);
	if (rc < 0)
		goto wrapup;
	rc = send(conn, (char*)httpPacket.data(), (int)httpPacket.size(), 0);
	if (rc <= 0) {
		rc = -1;
		goto wrapup;
	}
	rc = parseResponse(conn, response);
	if (rc < 0)
		goto wrapup;
	packetReader = response.data();
	packetReaderEnd = response.data() + response.size();
	rc = readServerHello();
	if (rc < 0)
		goto wrapup;
	rc = computeTrafficKey(session->pskAccess, hkdfExpand("handshake key expansion", handshakeHasher), trafficKey);
	if (rc < 0)
		goto wrapup;
	session->appKey = trafficKey;
	rc = readServerFinish();
	if (rc < 0)
		goto wrapup;
	rc = readDataRecord(dataRecord);
	if (rc < 0)
		goto wrapup;
	rc = readAbort();
	if (rc < 0)
		goto wrapup;
	resp = dataRecord.data;
wrapup:
	packetReader = nullptr;
	packetReaderEnd = nullptr;
	LL_INFO("Short link request end!!!!error_code: %d", rc);
	return rc;
}

int MMTLSClientShort::Close() {
	if (conn != NULL) {
#if defined(_WIN32)
		closesocket(conn);
#else
		close(conn);
#endif
		conn = NULL;
	}
	return 0;
}

int MMTLSClientShort::packHttp(const std::string& host, const std::string& path, const byteArray& req, byteArray& resp) {
	int rc = 0;
	byteArray tlsPayload, datPart;
	rc = genDataPart(host, path, req, datPart);
	if (rc < 0)
		return rc;
	clientHello hello = clientHello::newPskZeroHello(session->tk.tickets[0]);
	byteArray helloPart = hello.serialize();
	handshakeHasher->Write(helloPart);
	trafficKeyPair earlyKey;
	rc = earlyDataKey(session->pskAccess, session->tk.tickets[0], earlyKey);
	if (rc < 0)
		return rc;
	byteArray recordData = mmtlsRecord::createSystemRecord(helloPart).serialize();
	tlsPayload.insert(tlsPayload.end(), recordData.begin(), recordData.end());
	clientSeqNum++;
	// Extensions
	byteArray extensionsPart = {
		0x00, 0x00, 0x00, 0x10, 0x08, 0x00, 0x00, 0x00,
		0x0b, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x12,
		0x00, 0x00, 0x00, 0x00
	};
	for (int i = 0; i < 4; i++) {
		extensionsPart[16LL + i] = (hello.timestamp >> (24 - i * 8)) & 0xff;
	}
	handshakeHasher->Write(extensionsPart);
	mmtlsRecord extensionsRecord = mmtlsRecord::createSystemRecord(extensionsPart);
	rc = extensionsRecord.encrypt(earlyKey, clientSeqNum);
	if (rc < 0)
		return rc;
	recordData = extensionsRecord.serialize();
	tlsPayload.insert(tlsPayload.end(), recordData.begin(), recordData.end());
	clientSeqNum++;
	// Request
	mmtlsRecord requestRecord = mmtlsRecord::createRawDataRecord(datPart);
	rc = requestRecord.encrypt(earlyKey, clientSeqNum);
	if (rc < 0)
		return rc;
	recordData = requestRecord.serialize();
	tlsPayload.insert(tlsPayload.end(), recordData.begin(), recordData.end());
	clientSeqNum++;
	// Abort
	byteArray abortPart = { 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x01 };
	mmtlsRecord abortRecord = mmtlsRecord::createAbortRecord(abortPart);
	abortRecord.encrypt(earlyKey, clientSeqNum);
	recordData = abortRecord.serialize();
	tlsPayload.insert(tlsPayload.end(), recordData.begin(), recordData.end());
	clientSeqNum++;
	byteArray header;
	rc = buildRequestHeader(host, (int)tlsPayload.size(), header);
	if (rc < 0)
		return rc;
	header.insert(header.end(), tlsPayload.begin(), tlsPayload.end());
	resp = std::move(header);
	LL_INFO(toHexString(std::string(resp.begin(), resp.end())).c_str());
	return rc;
}

int MMTLSClientShort::genDataPart(const std::string& host, const std::string& path, const byteArray& req, byteArray& resp) {
	int rc = 0;
	byteArray result(4, 0);
	rc = writeU16LenData(result, byteArray(path.begin(), path.end()));
	if (rc < 0)
		return rc;
	rc = writeU16LenData(result, byteArray(host.begin(), host.end()));
	if (rc < 0)
		return rc;
	rc = writeU32LenData(result, req);
	if (rc < 0)
		return rc;
	uint32 length = (uint32)result.size() - 4;
	for (int i = 0; i < 4; i++) {
		result[i] = (length >> (24 - i * 8)) & 0xff;
	}
	resp = std::move(result);
	return rc;
}

int MMTLSClientShort::buildRequestHeader(const std::string& host, int length, byteArray& resp) {
	int rc = 0;
	byteArray randArr = getRandom(2);
	int randName = (0 << 24) | (0 << 16) | (randArr[0] << 8) | (randArr[1] << 0);
	std::string _headerFormat = "POST /mmtls/%08x HTTP/1.1\r\nHost: %s\r\nAccept: */*\r\nCache-Control: no-cache\r\nConnection: Keep-Alive\r\nContent-Length: %d\r\nContent-Type: application/octet-stream\r\nUpgrade: mmtls\r\nUser-Agent: MicroMessenger Client\r\n\r\n";
	size_t bLen = _headerFormat.length() + host.length() + 8 + 11;
	char* buffer = new char[bLen]();
#if defined(_WIN32)
	sprintf_s(buffer, bLen, _headerFormat.c_str(), randName, host.c_str(), length);
#else
	snprintf(buffer, bLen, _headerFormat.c_str(), randName, host.c_str(), length);
#endif
	std::string szHeader(buffer);
	delete[] buffer;
	resp = byteArray(szHeader.begin(), szHeader.end());
	return rc;
}

int MMTLSClientShort::parseResponse(SOCKET connection, byteArray& resp) {
	int rc = 0;
	char buf[1024] = { 0 };
	byteArray result;
	while (1) {
		memset(buf, 0, sizeof(buf));
		rc = recv(connection, buf, sizeof(buf), 0);
		if (rc < 0)
			return rc;
		if (rc == 0)
			break;
		result.insert(result.end(), buf, buf + rc);
	}
	// skip response header
	std::string szResp(result.begin(), result.end());
	size_t pos = 0;
	for (int i = 0; i <= (int)(szResp.length() - 4); i++) {
		std::string tmp = szResp.substr(i, 4);
		if (tmp == "\r\n\r\n") {
			pos = i;
			break;
		}
	}
	if (pos == 0)
		return -1;
	szRespHeader = szResp.substr(0, pos + 4);
	result = byteArray(result.begin() + pos + 4, result.end());
	resp = std::move(result);
	LL_INFO(toHexString(std::string(resp.begin(), resp.end())).c_str());
	return rc;
}

int MMTLSClientShort::readServerHello() {
	int rc = 0;
	mmtlsRecord serverHelloRecord = mmtlsRecord::readRecord(packetReader, packetReaderEnd, rc);
	if (rc < 0)
		return rc;
	packetReader += (5 + (size_t)serverHelloRecord.length);
	handshakeHasher->Write(serverHelloRecord.data);
	serverSeqNum++;
	LL_INFO(toHexString(std::string(serverHelloRecord.data.begin(), serverHelloRecord.data.end())).c_str());
	return rc;
}

int MMTLSClientShort::readServerFinish() {
	int rc = 0;
	mmtlsRecord record = mmtlsRecord::readRecord(packetReader, packetReaderEnd, rc);
	if (rc < 0)
		return rc;
	packetReader += (5 + (size_t)record.length);
	rc = record.decrypt(session->appKey, serverSeqNum);
	if (rc < 0)
		return rc;
	// TODO: verify server finished
	serverSeqNum++;
	LL_INFO(toHexString(std::string(record.data.begin(), record.data.end())).c_str());
	return rc;
}

int MMTLSClientShort::readDataRecord(mmtlsRecord& record) {
	int rc = 0;
	record = mmtlsRecord::readRecord(packetReader, packetReaderEnd, rc);
	if (rc < 0)
		return rc;
	packetReader += (5 + (size_t)record.length);
	rc = record.decrypt(session->appKey, serverSeqNum);
	if (rc < 0)
		return rc;
	serverSeqNum++;
	LL_INFO(toHexString(std::string(record.data.begin(), record.data.end())).c_str());
	return rc;
}

int MMTLSClientShort::readAbort() {
	int rc = 0;
	mmtlsRecord record = mmtlsRecord::readRecord(packetReader, packetReaderEnd, rc);
	if (rc < 0)
		return rc;
	packetReader += (5 + (size_t)record.length);
	rc = record.decrypt(session->appKey, serverSeqNum);
	if (rc < 0)
		return rc;
	serverSeqNum++;
	LL_INFO(toHexString(std::string(record.data.begin(), record.data.end())).c_str());
	return rc;
}

int MMTLSClientShort::earlyDataKey(const byteArray& pskAccess, const sessionTicket& ticket, trafficKeyPair& pair) {
	int rc = 0;
	byteArray trafficKey = ::hkdfExpand(EVP_sha256(), pskAccess, hkdfExpand("early data key expansion", handshakeHasher), 28);
	pair.clientKey = byteArray(trafficKey.begin(), trafficKey.begin() + 16);
	pair.clientNonce = byteArray(trafficKey.begin() + 16, trafficKey.end());
	return rc;
}

int MMTLSClientShort::computeTrafficKey(const byteArray& shareKey, const byteArray& info, trafficKeyPair& pair) {
	int rc = 0;
	byteArray trafficKey = ::hkdfExpand(EVP_sha256(), shareKey, info, 28);
	pair.serverKey = byteArray(trafficKey.begin(), trafficKey.begin() + 16);
	pair.serverNonce = byteArray(trafficKey.begin() + 16, trafficKey.end());
	return rc;
}

byteArray MMTLSClientShort::hkdfExpand(const std::string& prefix, const HandshakeHasher* hash) {
	byteArray result(prefix.begin(), prefix.end());
	if (hash != nullptr) {
		byteArray hashSum;
		int rc = handshakeHasher->Sum(hashSum);
		if (rc >= 0)
			result.insert(result.end(), hashSum.begin(), hashSum.end());
	}
	return result;
}

byteArray MMTLSClientShort::hmac(const byteArray& k, const byteArray& d) {
	byteArray result(SHA256_DIGEST_LENGTH, 0);
	HMAC_CTX* ctx = HMAC_CTX_new();
	unsigned outlen = 0, ret = 0;
	ret = HMAC_Init_ex(ctx, k.data(), (unsigned)k.size(), EVP_sha256(), NULL);
	ret = HMAC_Update(ctx, d.data(), d.size());
	ret = HMAC_Final(ctx, result.data(), &outlen);
	HMAC_CTX_free(ctx);
	return result;
}
