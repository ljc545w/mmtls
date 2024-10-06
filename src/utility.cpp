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

#if OPENSSL_API_LEVEL >= 30000
int EVP_EC_KEY_oct2key(EVP_PKEY* key, const unsigned char* buf, size_t len) {
	int rc = 0;
	EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	OSSL_PARAM ossl_params[] = {
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char*>(SN_X9_62_prime256v1), strlen(SN_X9_62_prime256v1)),
		OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, const_cast<unsigned char*>(buf), len),
		OSSL_PARAM_END
	};
	rc = EVP_PKEY_fromdata_init(pctx);
	if (!rc)
		goto wrapup;
	rc = EVP_PKEY_set_type(key, EVP_PKEY_EC);
	if (!rc)
		goto wrapup;
	rc = EVP_PKEY_fromdata(pctx, &key, EVP_PKEY_PUBLIC_KEY, ossl_params);
	if (!rc)
		goto wrapup;
wrapup:
	EVP_PKEY_CTX_free(pctx);
	return rc;
}

int EVP_EC_KEY_key2buf(const EVP_PKEY* key, std::string& outData) {
	int rc = 0;
	OSSL_PARAM* ossl_params = nullptr;
	rc = EVP_PKEY_todata(key, EVP_PKEY_PUBLIC_KEY, &ossl_params);
	if (!rc)
		return rc;
	rc = 0;
	OSSL_PARAM* p_cur = ossl_params;
	while (p_cur->data) {
		std::string szKey(p_cur->key);
		if (szKey == OSSL_PKEY_PARAM_PUB_KEY) {
			outData = std::string((char*)p_cur->data, p_cur->data_size);
			rc = 1;
			break;
		}
		p_cur += 1;
	}
	return rc;
}

int EVP_EC_KEY_get0_public_key(const EC_GROUP* curve, const EVP_PKEY* key, EC_POINT** ppEcPoint) {
	int rc = 0;
	OSSL_PARAM* ossl_params = nullptr;
	std::string szKeyBuf;
	rc = EVP_PKEY_todata(key, EVP_PKEY_KEYPAIR, &ossl_params);
	if (!rc)
		return rc;
	rc = 0;
	OSSL_PARAM* p_cur = ossl_params;
	while (p_cur->data) {
		std::string szKey(p_cur->key);
		if (szKey == OSSL_PKEY_PARAM_PUB_KEY) {
			szKeyBuf = std::string((char*)p_cur->data, p_cur->data_size);
			rc = 1;
			break;
		}
		p_cur += 1;
	}
	if (!rc)
		return rc;
	EC_POINT* pEcPoint = EC_POINT_new(curve);
	rc = EC_POINT_oct2point(curve, pEcPoint, (unsigned char*)szKeyBuf.data(), szKeyBuf.size(), NULL);
	if (rc)
		*ppEcPoint = pEcPoint;
	else
		EC_POINT_free(pEcPoint);
	return rc;
}

int EVP_EC_KEY_get0_private_key(const EVP_PKEY* key, BIGNUM** ppBigNum) {
	int rc = 0;
	OSSL_PARAM* ossl_params = nullptr;
	std::string szKeyBuf;
	rc = EVP_PKEY_todata(key, EVP_PKEY_KEYPAIR, &ossl_params);
	if (!rc)
		return rc;
	rc = 0;
	OSSL_PARAM* p_cur = ossl_params;
	while (p_cur->data) {
		std::string szKey(p_cur->key);
		if (szKey == OSSL_PKEY_PARAM_PRIV_KEY) {
			szKeyBuf = std::string((char*)p_cur->data, p_cur->data_size);
			rc = 1;
			break;
		}
		p_cur += 1;
	}
	if (!rc)
		return rc;
	BIGNUM* pBigNum = BN_new();
	if (BN_bin2bn((unsigned char*)szKeyBuf.data(), (int)szKeyBuf.size(), pBigNum) == nullptr) {
		rc = 0;
		BN_free(pBigNum);
	}
	else {
		rc = 1;
		*ppBigNum = pBigNum;
	}
	return rc;
}
#endif