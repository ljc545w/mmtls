#include "record.h"
#include "utility.h"
#include "const.h"
#include "mmtls_openssl.h"
#include <algorithm>

byteArray dataRecord::serialize() {
	byteArray result;
	unsigned length = (unsigned)data.size() + 16;
	for (int i = 0; i < 4; i++) {
		result.push_back((length >> (24 - i * 8)) & 0xff);
	}
	result.insert(result.end(), { 0x00,0x10 });
	result.insert(result.end(), { 0x00,0x01 });
	for (int i = 0; i < 4; i++) {
		result.push_back((dataType >> (24 - i * 8)) & 0xff);
	}
	for (int i = 0; i < 4; i++) {
		result.push_back((seq >> (24 - i * 8)) & 0xff);
	}
	if (data.size() > 0)
		result.insert(result.end(), data.begin(), data.end());
	return result;
}

mmtlsRecord mmtlsRecord::createRecord(uint8 recordType, const byteArray& data) {
	mmtlsRecord r;
	r.recordType = recordType;
	r.version = ProtocolVersion;
	r.length = data.size() & 0xffff;
	r.data = data;
	return r;
}
mmtlsRecord mmtlsRecord::readRecord(BYTE* pBufBegin, BYTE* pBufEnd, int& err) {
	mmtlsRecord r;
	BYTE* lBuf = pBufBegin;
	r.recordType = lBuf[0];
	lBuf++;
	r.version = (lBuf[0] << 8) | lBuf[1];
	lBuf += 2;
	r.length = (lBuf[0] << 8) | lBuf[1];
	lBuf += 2;
	r.data = byteArray(lBuf, lBuf + r.length);
	lBuf += r.length;
	if (lBuf > pBufEnd)
		err = -1;
	return r;
}

byteArray mmtlsRecord::serialize() {
	byteArray result;
	result.push_back(recordType);
	result.push_back((version >> 8) & 0xff);
	result.push_back((version >> 0) & 0xff);
	result.push_back((length >> 8) & 0xff);
	result.push_back((length >> 0) & 0xff);
	result.insert(result.end(), data.begin(), data.end());
	return result;
}

int mmtlsRecord::encrypt(const trafficKeyPair& keys, uint32 clientSeqNum) {
	byteArray nonce(keys.clientNonce.begin(), keys.clientNonce.end());
	if (nonce.size() == 0)
		return -1;
	xorNonce(nonce, clientSeqNum);
	byteArray auddit(4, 0);
	for (int i = 0; i < 4; i++) {
		auddit.push_back((clientSeqNum >> (24 - i * 8)) & 0xff);
	}
	auddit.push_back(recordType);
	auddit.push_back((version >> 8) & 0xff);
	auddit.push_back((version >> 0) & 0xff);
	// GCM add 16-byte tag
	uint16 fillLen = length + AEAD_TAG_LEN;
	auddit.push_back((fillLen >> 8) & 0xff);
	auddit.push_back((fillLen >> 0) & 0xff);
	// aead encrypt
	EVP_CIPHER_CTX* ctx = nullptr;
	int len = 0;
	if (!(ctx = EVP_CIPHER_CTX_new()))
		return -1;
	/* Initialise the encryption operation. */
	const EVP_CIPHER* cipher = EVP_aes_128_gcm();
	byteArray ciphertext(data.size(), 0);
	if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL))
		return -1;
	if (1 != EVP_CIPHER_CTX_set_key_length(ctx, (unsigned)keys.clientKey.size()))
		return -1;
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (unsigned)nonce.size(), NULL))
		return -1;
	if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, keys.clientKey.data(), nonce.data()))
		return -1;
	if (1 != EVP_EncryptUpdate(ctx, NULL, &len, auddit.data(), (unsigned)auddit.size()))
		return -1;
	if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, data.data(), (unsigned)data.size()))
		return -1;
	int ciphertext_len = len;
	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len))
		return -1;
	ciphertext_len += len;
	BYTE tag[AEAD_TAG_LEN] = { 0 };
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AEAD_TAG_LEN, tag))
		return -1;
	EVP_CIPHER_CTX_free(ctx);
	byteArray dst(ciphertext.begin(), ciphertext.begin() + ciphertext_len);
	dst.insert(dst.end(), tag, tag + sizeof(tag));
	data = std::move(dst);
	length = (uint16)data.size();
	return 0;
}

int mmtlsRecord::decrypt(const trafficKeyPair& keys, uint32 serverSeqNum) {
	byteArray nonce(keys.serverNonce.begin(), keys.serverNonce.end());
	xorNonce(nonce, serverSeqNum);
	byteArray auddit(4, 0);
	for (int i = 0; i < 4; i++) {
		auddit.push_back((serverSeqNum >> (24 - i * 8)) & 0xff);
	}
	auddit.push_back(recordType);
	auddit.push_back((version >> 8) & 0xff);
	auddit.push_back((version >> 0) & 0xff);
	auddit.push_back((length >> 8) & 0xff);
	auddit.push_back((length >> 0) & 0xff);
	// aead decrypt
	EVP_CIPHER_CTX* ctx = nullptr;
	int len = 0;
	if (!(ctx = EVP_CIPHER_CTX_new()))
		return -1;
	const EVP_CIPHER* cipher = EVP_aes_128_gcm();
	/* Initialise the encryption operation. */
	byteArray plaintext(data.size(), 0);
	if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL))
		return -1;
	if (1 != EVP_CIPHER_CTX_set_key_length(ctx, (unsigned)keys.serverKey.size()))
		return -1;
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (unsigned)nonce.size(), NULL))
		return -1;
	if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, keys.serverKey.data(), nonce.data()))
		return -1;
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AEAD_TAG_LEN, data.data() + data.size() - AEAD_TAG_LEN))
		return -1;
	if (1 != EVP_DecryptUpdate(ctx, NULL, &len, auddit.data(), (unsigned)auddit.size()))
		return -1;
	if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, data.data(), (unsigned)data.size() - AEAD_TAG_LEN))
		return -1;
	int plaintext_len = len;
	int rc = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
	EVP_CIPHER_CTX_free(ctx);
	if (rc > 0) {
		plaintext_len += len;
	}
	else {
		// tag verify failed.
		return -1;
	}
	byteArray dst(plaintext.begin(), plaintext.begin() + plaintext_len);
	data = std::move(dst);
	length = (uint16)data.size();
	return 0;
}