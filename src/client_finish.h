#pragma once
#include "custom_defs.h"

struct clientFinishTag {
	BYTE reversed = 0;
	byteArray data;
};

class clientFinish : public clientFinishTag {
public:
	static clientFinish newClientFinish(const byteArray& data);
	byteArray serialize();
};