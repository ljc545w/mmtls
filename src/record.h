#pragma once
#include "custom_defs.h"
#include "session.h"
#include "const.h"

struct dataRecordTag {
	uint32 dataType = 0;
	uint32 seq = 0;
	byteArray data;
};

struct mmtlsRecordTag {
	uint8 recordType = 0;
	uint16 version = 0;
	uint16 length = 0;
	byteArray data;
};

class dataRecord : public dataRecordTag {
public:
	dataRecord(uint32 dataType, uint32 seq, const byteArray& data){
		this->dataType = dataType;
		this->seq = seq;
		this->data = data;
	};
	byteArray serialize();
};

class mmtlsRecord : public mmtlsRecordTag {
public:
	static mmtlsRecord createRecord(uint8 recordType, const byteArray& data);
	static mmtlsRecord readRecord(BYTE* pBuf, BYTE* pBufEnd, int& err);
	static mmtlsRecord createAbortRecord(const byteArray& data) {
		return mmtlsRecord::createRecord(MagicAbort, data);
	}
	static mmtlsRecord createHandshakeRecord(const byteArray& data) {
		return mmtlsRecord::createRecord(MagicHandshake, data);
	}
	static mmtlsRecord createDataRecord(uint32 dataType, uint32 seq, const byteArray& data) {
		dataRecord r(dataType,seq,data);
		return mmtlsRecord::createRecord(MagicRecord, r.serialize());
	}
	static mmtlsRecord createRawDataRecord(const byteArray& data) {
		return mmtlsRecord::createRecord(MagicRecord, data);
	}
	static mmtlsRecord createSystemRecord(const byteArray& data) {
		return mmtlsRecord::createRecord(MagicSystem, data);
	}
	byteArray serialize();
	int encrypt(const trafficKeyPair& keys, uint32 clientSeqNum);
	int decrypt(const trafficKeyPair& keys, uint32 serverSeqNum);
};