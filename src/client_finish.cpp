#include "client_finish.h"

clientFinish clientFinish::newClientFinish(const byteArray& data) {
	clientFinish cf;
	cf.reversed = 0x14;
	cf.data = data;
	return cf;
}

byteArray clientFinish::serialize() {
	byteArray result;
	UINT32 dLen = (UINT32)(data.size() + 3);
	result.push_back((dLen >> 24) & 0xff);
	result.push_back((dLen >> 16) & 0xff);
	result.push_back((dLen >> 8) & 0xff);
	result.push_back((dLen >> 0) & 0xff);
	result.push_back(reversed);
	dLen = (uint32)data.size();
	result.push_back((dLen >> 8) & 0xff);
	result.push_back((dLen >> 0) & 0xff);
	result.insert(result.end(), data.begin(), data.end());
	return result;
}