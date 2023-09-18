#include "session.h"
#include "utility.h"

#if !defined(_WIN32)
#include <memory>
#endif

Session::Session(const newSessionTicket& tickets, const byteArray& pskAccess, const byteArray& pskRefresh) {
	this->tk = tickets;
	this->pskAccess = pskAccess;
	this->pskRefresh = pskRefresh;
}

bool Session::Save(const std::string& path) {
	std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
	if (!ofs.good())
		return false;
	byteArray buf;
	writeU16LenData(buf, pskAccess);
	writeU16LenData(buf, pskRefresh);
	byteArray ticketBytes = tk.serialize();
	buf.insert(buf.end(), ticketBytes.begin(), ticketBytes.end());
	ofs.write((char*)buf.data(), buf.size());
	ofs.close();
	return true;
}

int Session::loadSession(const std::string& path, Session& s) {
	int err = 0;
	std::ifstream ifs(path, std::ios::binary);
	if (!ifs.good()) {
		err = -1;
		return err;
	}
	ifs.seekg(0, std::ios::end);
	size_t fLen = ifs.tellg();
	ifs.seekg(0, std::ios::beg);
	std::unique_ptr<char[]> buffer = std::make_unique<char[]>(fLen);
	ifs.read(buffer.get(), fLen);
	ifs.close();
	BYTE* pBuf = (BYTE*)buffer.get();
	BYTE* pBufEnd = pBuf + fLen;
	UINT32 length = 0;
	s.pskAccess = readU16LenData(pBuf, length);
	pBuf += (sizeof(USHORT) + length);
	s.pskRefresh = readU16LenData(pBuf, length);
	pBuf += (sizeof(USHORT) + length);
	byteArray ticketBytes(pBuf, pBufEnd);
	s.tk = readNewSessionTicket(ticketBytes, err);
	return err;
}