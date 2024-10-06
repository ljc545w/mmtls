#include "client_hello.h"
#include "const.h"
#include "utility.h"

#if defined(_WIN32)
#include <string>
#pragma warning(disable: 26451)
#else
#include <time.h>
#include <ctime>
#endif

#ifndef OPENSSL3
clientHello clientHello::newECDHEHello(const EC_KEY* cliPubKey, const EC_KEY* cliVerKey) {
	clientHello ch;
	ch.protocolVersion = ProtocolVersion;
	ch.timestamp = (uint32)time(0);
	ch.random = getRandom(32);
	ch.cipherSuites.push_back(TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 & 0xffff);
	BYTE* pointBuf = nullptr;
	size_t bLen = EC_KEY_key2buf(cliPubKey, POINT_CONVERSION_UNCOMPRESSED, &pointBuf, nullptr);
	byteArray pubArr(pointBuf, pointBuf + bLen);
	OPENSSL_free(pointBuf);
	pointBuf = nullptr;
	bLen = EC_KEY_key2buf(cliVerKey, POINT_CONVERSION_UNCOMPRESSED, &pointBuf, nullptr);
	byteArray verArr(pointBuf, pointBuf + bLen);
	OPENSSL_free(pointBuf);
	pointBuf = nullptr;
	ch.extensions[TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 & 0xffff] = { pubArr,verArr };
	return ch;
}

clientHello clientHello::newPskOneHello(const EC_KEY* cliPubKey, const EC_KEY* cliVerKey, sessionTicket& ticket) {
	clientHello ch;
	ch.protocolVersion = ProtocolVersion;
	ch.timestamp = (uint32)time(0);
	ch.random = getRandom(32);
	ch.cipherSuites.push_back(TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 & 0xffff);
	ch.cipherSuites.push_back(TLS_PSK_WITH_AES_128_GCM_SHA256);
	sessionTicket& t = ticket;
	t.ticketAgeAdd = byteArray();
	byteArray ticketData = t.serialize();
	ch.extensions[TLS_PSK_WITH_AES_128_GCM_SHA256] = { ticketData };
	BYTE* pointBuf = nullptr;
	size_t bLen = EC_KEY_key2buf(cliPubKey, POINT_CONVERSION_UNCOMPRESSED, &pointBuf, nullptr);
	byteArray pubArr(pointBuf, pointBuf + bLen);
	OPENSSL_free(pointBuf);
	pointBuf = nullptr;
	bLen = EC_KEY_key2buf(cliVerKey, POINT_CONVERSION_UNCOMPRESSED, &pointBuf, nullptr);
	byteArray verArr(pointBuf, pointBuf + bLen);
	OPENSSL_free(pointBuf);
	pointBuf = nullptr;
	ch.extensions[TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 & 0xffff] = { pubArr,verArr };
	return ch;
}
#else
clientHello clientHello::newECDHEHello(const EVP_PKEY* cliPubKey, const EVP_PKEY* cliVerKey) {
	clientHello ch;
	ch.protocolVersion = ProtocolVersion;
	ch.timestamp = (uint32)time(0);
	ch.random = getRandom(32);
	ch.cipherSuites.push_back(TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 & 0xffff);
	std::string szCliPubKey, szCliVerKey;
	EVP_EC_KEY_key2buf(cliPubKey, szCliPubKey);
	byteArray pubArr(szCliPubKey.begin(), szCliPubKey.end());
	EVP_EC_KEY_key2buf(cliVerKey, szCliVerKey);
	byteArray verArr(szCliVerKey.begin(), szCliVerKey.end());
	ch.extensions[TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 & 0xffff] = { pubArr,verArr };
	return ch;
}

clientHello clientHello::newPskOneHello(const EVP_PKEY* cliPubKey, const EVP_PKEY* cliVerKey, sessionTicket& ticket) {
	clientHello ch;
	ch.protocolVersion = ProtocolVersion;
	ch.timestamp = (uint32)time(0);
	ch.random = getRandom(32);
	ch.cipherSuites.push_back(TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 & 0xffff);
	ch.cipherSuites.push_back(TLS_PSK_WITH_AES_128_GCM_SHA256);
	sessionTicket& t = ticket;
	t.ticketAgeAdd = byteArray();
	byteArray ticketData = t.serialize();
	ch.extensions[TLS_PSK_WITH_AES_128_GCM_SHA256] = { ticketData };
	std::string szCliPubKey, szCliVerKey;
	EVP_EC_KEY_key2buf(cliPubKey, szCliPubKey);
	byteArray pubArr(szCliPubKey.begin(), szCliPubKey.end());
	EVP_EC_KEY_key2buf(cliVerKey, szCliVerKey);
	byteArray verArr(szCliVerKey.begin(), szCliVerKey.end());
	ch.extensions[TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 & 0xffff] = { pubArr,verArr };
	return ch;
}
#endif

clientHello clientHello::newPskZeroHello(sessionTicket& ticket) {
	clientHello ch;
	ch.protocolVersion = ProtocolVersion;
	ch.timestamp = (uint32)time(0);
	ch.random = getRandom(32);
	ch.cipherSuites.push_back(TLS_PSK_WITH_AES_128_GCM_SHA256);
	sessionTicket& t = ticket;
	t.ticketAgeAdd = byteArray();
	byteArray ticketData = t.serialize();
	ch.extensions[TLS_PSK_WITH_AES_128_GCM_SHA256] = { ticketData };
	return ch;
}
byteArray clientHello::serialize() {
	byteArray result(4, 0x00); // total length
	result.push_back(0x01);	// flag
	// protocol version, little endian
	result.push_back((protocolVersion >> 0) & 0xff);
	result.push_back((protocolVersion >> 8) & 0xff);
	// cipher suites
	result.push_back(cipherSuites.size() & 0xff);
	for (auto cipherSuite : cipherSuites) {
		result.push_back((cipherSuite >> 8) & 0xff);
		result.push_back((cipherSuite >> 0) & 0xff);
	}
	// random
	for (unsigned i = 0; i < random.size(); i++) {
		result.push_back(random[i]);
	}
	// timestamp, big endian
	for (int i = 0; i < 4; i++) {
		result.push_back((timestamp >> (24 - i * 8)) & 0xff);
	}
	unsigned cipherPos = (unsigned)result.size();
	for (int i = 0; i < 4; i++) {
		result.push_back(0);
	}
	result.push_back(cipherSuites.size() & 0xff);
	for (int si = (int)(cipherSuites.size() - 1); si >= 0; si--) {
		uint16 cipher = cipherSuites[si];
		if (cipher == TLS_PSK_WITH_AES_128_GCM_SHA256) {
			unsigned pskPos = (unsigned)result.size();
			for (int i = 0; i < 4; i++) {
				result.push_back(0x00);
			}
			result.push_back(0x00);
			result.push_back(0x0F);
			result.push_back(0x01);
			unsigned keyPos = (unsigned)result.size();
			for (int i = 0; i < 4; i++) {
				result.push_back(0);
			}
			auto& extension = extensions[cipher][0];
			for (unsigned i = 0; i < extension.size(); i++) {
				result.push_back(extension[i]);
			}
			unsigned keyLen = (unsigned)result.size() - keyPos - 4;
			for (int i = 0; i < 4; i++) {
				result[keyPos + i] = ((keyLen >> (24 - i * 8)) & 0xff);
			}
			unsigned pskLen = (unsigned)result.size() - pskPos - 4;
			for (int i = 0; i < 4; i++) {
				result[pskPos + i] = ((pskLen >> (24 - i * 8)) & 0xff);
			}
		}
		else if (cipher == (TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 & 0xffff)) {
			unsigned ecdsaPos = (unsigned)result.size();
			for (int i = 0; i < 4; i++) {
				result.push_back(0x00);
			}
			result.push_back(0x00);
			result.push_back(0x10);
			result.push_back(extensions[cipher].size() & 0xff);
			uint32 keyFlag = 5;
			for (auto& extension : extensions[cipher]) {
				unsigned keyPos = (unsigned)result.size();
				for (int i = 0; i < 4; i++) {
					result.push_back(0x00);
				}
				for (int i = 0; i < 4; i++) {
					result.push_back((keyFlag >> (24 - i * 8)) & 0xff);
				}
				keyFlag++;
				result.push_back((extension.size() >> 8) & 0xff);
				result.push_back((extension.size() >> 0) & 0xff);
				for (unsigned i = 0; i < extension.size(); i++) {
					result.push_back(extension[i]);
				}
				unsigned keyLen = (unsigned)result.size() - keyPos - 4;
				for (int i = 0; i < 4; i++) {
					result[keyPos + i] = ((keyLen >> (24 - i * 8)) & 0xff);
				}
			}
			byteArray magic = { 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04 };
			result.insert(result.end(), magic.begin(), magic.end());
			// ecdsa length
			unsigned ecdsaLen = (unsigned)result.size() - ecdsaPos - 4;
			for (int i = 0; i < 4; i++) {
				result[ecdsaPos + i] = ((ecdsaLen >> (24 - i * 8)) & 0xff);
			}
		}
		else {
			throw std::runtime_error(("cipher(" + std::to_string(cipher) + ") not support").c_str());
		}
	}
	// cipher length
	unsigned cLen = (unsigned)result.size() - cipherPos - 4;
	for (int i = 0; i < 4; i++) {
		result[cipherPos + i] = ((cLen >> (24 - i * 8)) & 0xff);
	}
	// struct length
	unsigned tLen = (unsigned)result.size() - 4;
	for (int i = 0; i < 4; i++) {
		result[i] = ((tLen >> (24 - i * 8)) & 0xff);
	}
	return result;
}