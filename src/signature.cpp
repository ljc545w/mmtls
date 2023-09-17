#include "signature.h"

signature signature::readSignature(BYTE* pBuf, int& err) {
	signature sign;
	BYTE* lBuf = pBuf;
	// skip package length
	lBuf += 4;
	// static 0x0f
	sign.Type = lBuf[0];
	lBuf++;
	uint16 length = (lBuf[0] << 8) | lBuf[1];
	lBuf += 2;
	sign.EcdsaSignature = byteArray(lBuf, lBuf + length);
	lBuf += length;
	err = 0;
	return sign;
}