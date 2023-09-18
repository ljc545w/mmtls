#pragma once
#include "custom_defs.h"

struct sessionTicketTag {
	BYTE ticketType = 0;					// reversed unknonw
	UINT32 ticketLifeTime = 0;
	byteArray ticketAgeAdd;
	UINT32 reversed = 0;					// always 0x48
	byteArray nonce;						// 12 bytes nonce
	byteArray ticket;
};

class sessionTicket : public sessionTicketTag {
public:
	byteArray serialize();
};

struct newSessionTicketTag {
	BYTE reversed = 0;
	BYTE count = 0;
	std::vector<sessionTicket> tickets;
};

class newSessionTicket : public newSessionTicketTag {
public:
	byteArray serialize();
	byteArray Export();
};

sessionTicket readSessionTicket(const byteArray& buf, int& err);
newSessionTicket readNewSessionTicket(const byteArray& buf, int& err);