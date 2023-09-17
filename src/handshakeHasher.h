#pragma once
#include "custom_defs.h"
#include <openssl/ec.h>
#include <openssl/evp.h>

class HandshakeHasher {
public:
	HandshakeHasher(const EVP_MD* evpMd) : m_EvpMd(evpMd) { };
	virtual ~HandshakeHasher() {};
	virtual int Write(const byteArray& info) {
		m_Content.insert(m_Content.end(), info.begin(), info.end());
		return (int)m_Content.size();
	};
	virtual void reset() {
		m_Content.clear();
	};
	virtual int Sum(byteArray& digest, const byteArray& extraInfo = {});
private:
	byteArray m_Content;
	const EVP_MD* m_EvpMd = nullptr;
};