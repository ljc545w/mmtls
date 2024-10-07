#include "mmtls.h"
#include "session.h"
#include "mmtls_short.h"

int main() 
{
	InitServerEcdh();
#if defined(_WIN32)
	WSADATA wsaData = { 0 };
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		goto wrapup;
#endif
	{
		int err = 0;
		MMTLSClient client;
		Session session;
		err = Session::loadSession("session", session);
		if (err == 0)
			client.session = &session;
		err = client.HandShake("long.weixin.qq.com");
		if(err >= 0)
			client.session->Save("session");
		if(err >= 0) 
			err = client.Noop();
		client.Close();
	}
	{
		int err = 0;
		MMTLSClientShort client;
		Session session;
		err = Session::loadSession("session", session);
		if (err == 0)
			client.session = &session;
		byteArray resp;
		err = client.Request("dns.weixin.qq.com.cn", "/cgi-bin/micromsg-bin/newgetdns", {}, resp);
		client.Close();
	}

#if defined(_WIN32)
wrapup:
	WSACleanup();
#endif
	UnInitServerEcdh();
	return 0;
}