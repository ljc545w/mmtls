#include "session_ticket.h"
#include "utility.h"

sessionTicket readSessionTicket(byteArray buf, int& err) {
	sessionTicket t;
	BYTE* pBuf = buf.data();
	UINT32 length = 0;
	t.ticketType = pBuf[0];
	pBuf++;
	t.ticketLifeTime = (pBuf[0] << 24) | (pBuf[1] << 16) | (pBuf[2] << 8) | (pBuf[3] << 0);
	pBuf += 4;
	t.ticketAgeAdd = readU16LenData(pBuf, length);
	pBuf += (sizeof(USHORT) + length);
	t.reversed = (pBuf[0] << 24) | (pBuf[1] << 16) | (pBuf[2] << 8) | (pBuf[3] << 0);
	pBuf += 4;
	t.nonce = readU16LenData(pBuf, length);
	pBuf += (sizeof(USHORT) + length);
	t.ticket = readU16LenData(pBuf, length);
	pBuf += (sizeof(USHORT) + length);
	return t;
}

newSessionTicket readNewSessionTicket(byteArray buf, int& err) {
	newSessionTicket t;
	BYTE* pBuf = buf.data();
	UINT32 length = 0;
	length = (pBuf[0] << 24) | (pBuf[1] << 16) | (pBuf[2] << 8) | (pBuf[3] << 0);
	pBuf += 4;
	t.reversed = pBuf[0];
	pBuf++;
	t.count = pBuf[0];
	pBuf++;
	for (BYTE i = 0; i < t.count; i++) {
		length = (pBuf[0] << 24) | (pBuf[1] << 16) | (pBuf[2] << 8) | (pBuf[3] << 0);
		pBuf += 4;
		byteArray data(pBuf, pBuf + length);
		pBuf += length;
		auto ticket = readSessionTicket(data, err);
		t.tickets.push_back(ticket);
	}
	return t;
}

byteArray sessionTicket::serialize() {
	byteArray result;
	result.push_back(this->ticketType);
	for (unsigned i = 0; i < sizeof(this->ticketLifeTime); i++) {
		result.push_back((this->ticketLifeTime >> (24 - i * 8)) & 0xff);
	}
	writeU16LenData(result, this->ticketAgeAdd);
	for (unsigned i = 0; i < sizeof(this->ticketLifeTime); i++) {
		result.push_back((this->reversed >> (24 - i * 8)) & 0xff);
	}
	writeU16LenData(result, this->nonce);
	writeU16LenData(result, this->ticket);
	return result;
}

byteArray newSessionTicket::serialize() {
	byteArray result;
	for (int i = 0; i < 4; i++)
		result.push_back(0x0);
	result.push_back(0x04);
	result.push_back(0x02);
	for (auto& ticket : this->tickets) {
		auto vBytes = ticket.serialize();
		writeU32LenData(result, vBytes);
	}
	UINT32 dLen = (UINT32)(result.size() - 4);
	result[0] = (dLen >> 24) & 0xff;
	result[1] = (dLen >> 16) & 0xff;
	result[2] = (dLen >> 8) & 0xff;
	result[3] = (dLen >> 0) & 0xff;
	return result;
}

byteArray newSessionTicket::Export() {
	byteArray result;
	if (this->tickets.size() == 0)
		return result;
	auto data = this->tickets[0].serialize();
	writeU32LenData(result, data);
	return result;
}