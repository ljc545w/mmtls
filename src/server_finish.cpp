#include "server_finish.h"

serverFinish serverFinish::readServerFinish(BYTE* pBuf, int& err) {
	BYTE* lBuf = pBuf;
	serverFinish s;
	lBuf += 4;
	s.reversed = lBuf[0];
	lBuf++;
	uint16 length = (lBuf[0] << 8) | lBuf[1];
	lBuf += 2;
	s.data = byteArray(lBuf, lBuf + length);
	lBuf += length;
	err = 0;
	return s;
}