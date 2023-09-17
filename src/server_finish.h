#pragma once
#include "custom_defs.h"

struct serverFinishTag {
	BYTE reversed = 0;
	byteArray data;
};

class serverFinish : public serverFinishTag {
public:
	static serverFinish readServerFinish(BYTE* pBuf, int& err);
};