#include "const.h"
#include "server_hello.h"

serverHello serverHello::readServerHello(const byteArray& buf, int& err) {
	err = 0;
	serverHello hello;
	BYTE* lBuf = const_cast<BYTE*>(buf.data());
	uint32 packLen = 0;
	packLen = (lBuf[0] << 24) | (lBuf[1] << 16) | (lBuf[2] << 8) | (lBuf[3] << 0);
	lBuf += 4;
	if (buf.size() != packLen + 4) {
		throw std::runtime_error("data corrupted");
	}
	// skip flag
	lBuf++;
	hello.protocolVersion = (lBuf[0] << 8) | lBuf[1];
	lBuf += 2;
	hello.cipherSuites = (lBuf[0] << 8) | lBuf[1];
	lBuf += 2;
	// skip server random
	lBuf += 32;
	// skip exntensions package length
	lBuf += 4;
	// skip extensions count
	lBuf++;
	// skip extension package length
	lBuf += 4;
	// skip extension type
	lBuf += 2;
	// skip extension array index
	lBuf += 4;
	uint16 keyLen = (lBuf[0] << 8) | lBuf[1];
	lBuf += 2;
	byteArray ecPoint(lBuf, lBuf + keyLen);
	lBuf += keyLen;
	hello.publicKey = EC_KEY_new_by_curve_name(ServerEcdhCurve);
	int rc = EC_KEY_oct2key(hello.publicKey, ecPoint.data(), ecPoint.size(), nullptr);
	if (!rc) {
		err = -1;
	}
	return hello;
}