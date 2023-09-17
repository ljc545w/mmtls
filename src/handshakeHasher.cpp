#include "handshakeHasher.h"

int HandshakeHasher::Sum(byteArray& digest, const byteArray& extraInfo) {
	if(extraInfo.size() > 0)
		m_Content.insert(m_Content.end(), extraInfo.begin(), extraInfo.end());
	byteArray result(EVP_MAX_MD_SIZE, 0);
	unsigned dLen = 0;
	EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
	if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr))
		return -1;
	if (1 != EVP_DigestUpdate(mdctx, m_Content.data(), m_Content.size()))
		return -1;
	if (1 != EVP_DigestFinal_ex(mdctx, result.data(), &dLen))
		return -1;
	EVP_MD_CTX_free(mdctx);
	digest = byteArray(result.begin(), result.begin() + dLen);
	return 0;
}