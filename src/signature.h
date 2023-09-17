#pragma once
#include "custom_defs.h"

struct signatureTag {
	BYTE Type = 0;
	byteArray EcdsaSignature;
};

class signature : public signatureTag {
public:
	static signature readSignature(BYTE* pBuf, int& err);
};