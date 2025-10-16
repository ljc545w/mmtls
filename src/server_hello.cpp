#include "const.h"
#include "server_hello.h"
#include "utility.h"

serverHello serverHello::readServerHello(const byteArray& buf, int& err) {
	err = 0;
	serverHello hello;
	BYTE* lBuf = const_cast<BYTE*>(buf.data());
	uint32 packLen = 0;
	packLen = (lBuf[0] << 24) | (lBuf[1] << 16) | (lBuf[2] << 8) | (lBuf[3] << 0);
	lBuf += 4;
	if (buf.size() != (size_t)(packLen + 4)) {
		throw std::runtime_error("data corrupted");
	}
	// skip flag
	lBuf++;
	hello.protocolVersion = (lBuf[1] << 8) | lBuf[0];
	lBuf += 2;
	hello.cipherSuite = (lBuf[0] << 8) | lBuf[1];
	lBuf += 2;
	// server random
	hello.random = byteArray(lBuf, lBuf + 32);
	lBuf += 32;
	// extensions package length
	uint32 extensionsLen = 0;
	extensionsLen = (lBuf[0] << 24) | (lBuf[1] << 16) | (lBuf[2] << 8) | (lBuf[3] << 0);
	lBuf += 4;
	// skip extensions count
	uint32 extensionCount = 0;
	extensionCount = (uint32)lBuf[0];
	lBuf++;
	for (uint32 index = 0; index < extensionCount; index++) {
		// extension package length
		uint32 extensionPkgLen = 0;
		extensionPkgLen = (lBuf[0] << 24) | (lBuf[1] << 16) | (lBuf[2] << 8) | (lBuf[3] << 0);
		lBuf += 4;
		// extension type
		uint16 extensionType = 0;
		extensionType = (lBuf[0] << 8) | lBuf[1];
		lBuf += 2;
		// extension array index
		uint32 extensionArrayIndex = 0;
		extensionArrayIndex = (lBuf[0] << 24) | (lBuf[1] << 16) | (lBuf[2] << 8) | (lBuf[3] << 0);
		lBuf += 4;
		uint16 extensionLen = (lBuf[0] << 8) | lBuf[1];
		lBuf += 2;
		byteArray extension(lBuf, lBuf + extensionLen);
		lBuf += extensionLen;
		hello.extensions[extensionType].push_back(extension);
	}
	return hello;
}