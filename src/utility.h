#pragma once
#include "custom_defs.h"

byteArray getRandom(int n);
void xorNonce(byteArray& nonce, UINT32 seq);
byteArray readU16LenData(BYTE* pBuf, UINT32& refLen);
UINT32 writeU16LenData(byteArray& dst, const byteArray& src);
UINT32 writeU32LenData(byteArray& dst, const byteArray& src);
const std::string getHostByName(const std::string& hostName);