#include "mmtls.h"
#include "utility.h"
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <algorithm>
#include "signature.h"
#include "server_finish.h"
#include "client_finish.h"
#include "const.h"
#include "logger.hpp"

#if !defined(_WIN32)
#include<sys/select.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<netdb.h>
#endif

EC_KEY* ServerEcdh = nullptr;
EC_GROUP* curve = nullptr;

void InitServerEcdh() {
    if (ServerEcdh)
        return;
    if(curve == nullptr)
        curve = EC_GROUP_new_by_curve_name(ServerEcdhCurve);
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(ServerEcdhCurve);
    byteArray data(1, POINT_CONVERSION_UNCOMPRESSED);
    std::string x = bytesFromHex(ServerEcdhX);
    std::string y = bytesFromHex(ServerEcdhY);
    data.insert(data.end(), x.begin(), x.end());
    data.insert(data.end(), y.begin(), y.end());
    if (EC_KEY_oct2key(ec_key, data.data(), data.size(), nullptr))
        ServerEcdh = ec_key;
}

void UnInitServerEcdh() {
    if (!ServerEcdh)
        return;
    EC_KEY_free(ServerEcdh);
    ServerEcdh = nullptr;
    if (curve)
    {
        EC_GROUP_free(curve);
        curve = nullptr;
    }
}

static byteArray hkdfExpand(const EVP_MD* hasher, const byteArray& preudorandomKey, const byteArray& info, int length)
{
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    byteArray result(length, 0);
    size_t outlen = length, ret = 0;
    ret = EVP_PKEY_derive_init(pctx) <= 0
        || EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0
        || EVP_PKEY_CTX_set_hkdf_md(pctx, hasher) <= 0
        || EVP_PKEY_CTX_set1_hkdf_key(pctx, preudorandomKey.data(), (unsigned)preudorandomKey.size()) <= 0
        || EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), (unsigned)info.size()) <= 0
        || EVP_PKEY_derive(pctx, result.data(), &outlen) <= 0;
    EVP_PKEY_CTX_free(pctx);
    return result;
}

MMTLSClient::MMTLSClient() {
    handshakeHasher = new HandshakeHasher(EVP_sha256());
}

MMTLSClient::~MMTLSClient() {
    if (publicEcdh)
        EC_KEY_free(publicEcdh);
    if (verifyEcdh)
        EC_KEY_free(verifyEcdh);
    if (serverEcdh)
        EC_KEY_free(serverEcdh);
    if (handshakeHasher)
        delete handshakeHasher;
    if (m_bIsNewSession && session)
        delete session;
}

int MMTLSClient::HandShake(const std::string& host) {
    LL_INFO("Long link handshake begin!!!!");
    int rc = 0;
    sockaddr_in serverAddress = { 0 };
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(80);
    const std::string ip = getHostByName(host);
    clientHello ch;
    serverHello sh;
    const EC_POINT* serverPublicKey = nullptr;
    const BIGNUM* publicEcdhPrivateKey = nullptr;
    byteArray comKey, expandedSecret;
    trafficKeyPair trafficKey, appKey;
    if (conn == NULL) {
        conn = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (conn == INVALID_SOCKET) {
            rc = -1;
            goto wrapup;
        }
#if defined(_WIN32)
        InetPtonA(AF_INET, ip.c_str(), &serverAddress.sin_addr.s_addr);
#else
        inet_pton(AF_INET, ip.c_str(), &serverAddress.sin_addr.s_addr);
#endif
        if (connect(conn, reinterpret_cast<sockaddr*>(&serverAddress), sizeof(sockaddr)) == SOCKET_ERROR)
        {
            rc = -1;
            goto wrapup;
        }
    }
    if (handshakeComplete())
    {
        rc = -1;
        goto wrapup;
    }
    reset();
    if (genKeyPairs() < 0)
    {
        rc = -1;
        goto wrapup;
    }
    if (session != nullptr)
    {
        ch = clientHello::newPskOneHello(publicEcdh, verifyEcdh, session->tk.tickets[1]);
    }
    else {
        ch = clientHello::newECDHEHello(publicEcdh, verifyEcdh);
    }
    if (sendClientHello(ch) < 0)
    {
        rc = -1;
        goto wrapup;
    }
    if (readServerHello(sh) < 0) {
        rc = -1;
        goto wrapup;
    }
    // DH compute key
    serverPublicKey = EC_KEY_get0_public_key(sh.publicKey);
    publicEcdhPrivateKey = EC_KEY_get0_private_key(publicEcdh);
    comKey = computeEphemeralSecret(serverPublicKey, publicEcdhPrivateKey);
    // trafffic key
    if (computeTrafficKey(comKey, hkdfExpand("handshake key expansion", handshakeHasher), trafficKey) < 0)
    {
        rc = -1;
        goto wrapup;
    }
    // compare traffic key is valid
    if (readSignature(trafficKey) < 0)
    {
        rc = -1;
        goto wrapup;
    }
    // gen psk
    if (readNewSessionTicket(comKey, trafficKey) < 0)
    {
        rc = -1;
        goto wrapup;
    }
    if (readServerFinish(comKey, trafficKey) < 0)
    {
        rc = -1;
        goto wrapup;
    }
    if (sendClientFinish(comKey, trafficKey) < 0)
    {
        rc = -1;
        goto wrapup;
    }
    // ComputeMasterSecret
    expandedSecret = ::hkdfExpand(EVP_sha256(), comKey, hkdfExpand("expanded secret", handshakeHasher), 32);
    // AppKey
    if (computeTrafficKey(expandedSecret, hkdfExpand("application data key expansion", handshakeHasher), appKey) < 0)
    {
        rc = -1;
        goto wrapup;
    }
    session->appKey = appKey;
    // fully complete handshake
    status.store(1);
wrapup:
    LL_INFO("Long link handshake end!!!!error_code: %d", rc);
    return rc;
}

int MMTLSClient::Noop() {
    LL_INFO("Long link noop begin!!!!");
    int rc = 0;
    rc = sendNoop();
    if (rc >= 0)
    {
        rc = readNoop();
    }
    LL_INFO("Long link noop end!!!!error_code: %d", rc);
    return rc;
}

int MMTLSClient::Close() {
    int rc = 0;
    if (conn != NULL) {
#if defined(_WIN32)
        closesocket(conn);
#else
        close(conn);
#endif
    }
    return rc;
}

int MMTLSClient::reset() {
    int rc = 0;
    clientSeqNum = 0;
    serverSeqNum = 0;
    handshakeHasher->reset();
    return rc;
}

bool MMTLSClient::handshakeComplete() {
    return (status.load() == 1);
}

int MMTLSClient::sendClientHello(clientHello& hello) {
    int rc = 0;
    byteArray data = hello.serialize();
    handshakeHasher->Write(data);
    byteArray packet = mmtlsRecord::createHandshakeRecord(data).serialize();
    int sLen = send(conn, (char*)packet.data(), (int)packet.size(), 0);
    clientSeqNum++;
    if (sLen == -1)
        return -1;
    LL_INFO(toHexString(std::string(packet.begin(), packet.end())).c_str());
    return rc;
}

int MMTLSClient::readServerHello(serverHello& hello) {
    int rc = 0;
    mmtlsRecord record;
    rc = readRecord(record);
    if (rc < 0)
        return rc;
    handshakeHasher->Write(record.data);
    serverSeqNum++;
    hello = serverHello::readServerHello(record.data, rc);
    LL_INFO(toHexString(std::string(record.data.begin(), record.data.end())).c_str());
    return rc;
}

int MMTLSClient::readSignature(trafficKeyPair& trafficKey) {
    int rc = 0;
    mmtlsRecord record;
    rc = readRecord(record);
    if (rc < 0)
        return rc;
    rc = record.decrypt(trafficKey, serverSeqNum);
    if (rc < 0)
        return rc;
    signature sign = signature::readSignature(record.data.data(), rc);
    if (rc < 0)
        return rc;
    if (!verifyEcdsa(sign.EcdsaSignature))
        return -1;
    handshakeHasher->Write(record.data);
    serverSeqNum++;
    LL_INFO(toHexString(std::string(record.data.begin(), record.data.end())).c_str());
    return rc;
}

int MMTLSClient::readNewSessionTicket(const byteArray& comKey, const trafficKeyPair& trafficKey) {
    int rc = 0;
    mmtlsRecord record;
    rc = readRecord(record);
    if (rc < 0)
        return rc;
    rc = record.decrypt(trafficKey, serverSeqNum);
    if (rc < 0)
        return rc;
    newSessionTicket tickets = ::readNewSessionTicket(record.data,rc);
    if (rc < 0)
        return rc;
    byteArray pskAccess = ::hkdfExpand(EVP_sha256(), comKey, hkdfExpand("PSK_ACCESS", handshakeHasher), 32);
    byteArray pskRefresh = ::hkdfExpand(EVP_sha256(), comKey, hkdfExpand("PSK_REFRESH", handshakeHasher), 32);
    session = new Session(tickets, pskAccess, pskRefresh);
    m_bIsNewSession = true;
    handshakeHasher->Write(record.data);
    serverSeqNum++;
    LL_INFO(toHexString(std::string(record.data.begin(), record.data.end())).c_str());
    return rc;
}

int MMTLSClient::readServerFinish(const byteArray& comKey, const trafficKeyPair& trafficKey) {
    int rc = 0;
    mmtlsRecord record;
    rc = readRecord(record);
    if (rc < 0)
        return rc;
    rc = record.decrypt(trafficKey, serverSeqNum);
    if (rc < 0)
        return rc;
    serverFinish sf = serverFinish::readServerFinish(record.data.data(), rc);
    if (rc < 0)
        return rc;
    byteArray sfKey = ::hkdfExpand(EVP_sha256(), comKey, hkdfExpand("server finished", nullptr), 32);
    byteArray digest;
    rc = handshakeHasher->Sum(digest);
    if (rc < 0)
        return rc;
    byteArray securityParam = hmac(sfKey, digest);
    if (sf.data != securityParam)
        return -1;
    LL_INFO(toHexString(std::string(record.data.begin(), record.data.end())).c_str());
    serverSeqNum++;
    return rc;
}

int MMTLSClient::sendClientFinish(const byteArray& comKey, const trafficKeyPair& trafficKey) {
    int rc = 0;
    byteArray cliKey = ::hkdfExpand(EVP_sha256(), comKey, hkdfExpand("client finished", nullptr), 32);
    byteArray digest;
    rc = handshakeHasher->Sum(digest);
    if (rc < 0)
        return rc;
    cliKey = hmac(cliKey, digest);
    clientFinish cf = clientFinish::newClientFinish(cliKey);
    mmtlsRecord cfRecord = mmtlsRecord::createHandshakeRecord(cf.serialize());
    rc = cfRecord.encrypt(trafficKey, clientSeqNum);
    if (rc < 0)
        return rc;
    byteArray packet = cfRecord.serialize();
    int sLen = send(conn, (char*)packet.data(), (int)packet.size(), 0);
    clientSeqNum++;
    if (sLen == -1)
        return -1;
    LL_INFO(toHexString(std::string(packet.begin(), packet.end())).c_str());
    return rc;
}

int MMTLSClient::sendNoop() {
    int rc = 0;
    mmtlsRecord noop = mmtlsRecord::createDataRecord(TCP_NoopRequest, 0xffffffff, {});
    noop.encrypt(session->appKey, clientSeqNum);
    byteArray packet = noop.serialize();
    int sLen = send(conn, (char*)packet.data(), (int)packet.size(), 0);
    clientSeqNum++;
    if (sLen == -1)
        return -1;
    LL_INFO(toHexString(std::string(packet.begin(), packet.end())).c_str());
    return rc;
}

int MMTLSClient::readNoop() {
    int rc = 0;
    mmtlsRecord record;
    rc = readRecord(record);
    if (rc < 0)
        return rc;
    rc = record.decrypt(session->appKey, serverSeqNum);
    if (rc < 0)
        return rc;
    BYTE* pBuf = record.data.data();
    uint32 packLen = (pBuf[0] << 24) | (pBuf[1] << 16) | (pBuf[2] << 8) | (pBuf[3] << 0);
    pBuf += 4;
    if (packLen != 16)
        return -1;
    // skip flag
    pBuf += 4;
    uint32 dataType = (pBuf[0] << 24) | (pBuf[1] << 16) | (pBuf[2] << 8) | (pBuf[3] << 0);
    pBuf += 4;
    if (dataType != TCP_NoopResponse)
        return -1;
    LL_INFO(toHexString(std::string(record.data.begin(), record.data.end())).c_str());
    serverSeqNum++;
    return rc;
}

int MMTLSClient::readRecord(mmtlsRecord& record) {
    int rc = 0;
    if (conn == NULL)
        return -1;
    byteArray header(5, 0);
    int rLen = recv(conn, (char*)header.data(), 5, 0);
    if (rLen == -1 || rLen == 0)
        return -1;
    uint16 packLen = (header[3] << 8) | header[4];
    byteArray payload(packLen, 0);
    rLen = recv(conn, (char*)payload.data(), packLen, 0);
    if (rLen == -1 || rLen == 0)
        return -1;
    header.insert(header.end(), payload.begin(), payload.end());
    record = mmtlsRecord::readRecord(header.data(), header.data() + header.size(), rc);
    return rc;
}

byteArray MMTLSClient::computeEphemeralSecret(const EC_POINT* serverPublicKey, const BIGNUM* publicEcdhPrivateKey) {
    byteArray result(SHA256_DIGEST_LENGTH, 0);
    EC_POINT* point = EC_POINT_new(curve);
    int rc = 0;
    rc = EC_POINT_mul(curve, point, nullptr, serverPublicKey, publicEcdhPrivateKey, nullptr);
    BIGNUM * x = BN_new(), * y = BN_new();
    rc = EC_POINT_get_affine_coordinates(curve, point, x, y, nullptr);
    BYTE serialized[32] = { 0 };
    rc = BN_bn2bin(x, serialized);
    BN_free(x); BN_free(y); EC_POINT_free(point);
    SHA256_CTX sha256;
    rc = SHA256_Init(&sha256);
    rc = SHA256_Update(&sha256, serialized, sizeof(serialized));
    rc = SHA256_Final(result.data(), &sha256);
    return result;
}

int MMTLSClient::computeTrafficKey(const byteArray& shareKey, const byteArray& info, trafficKeyPair& pair) {
    int rc = 0;
    byteArray trafficKey = ::hkdfExpand(EVP_sha256(), shareKey, info, 56);
    BYTE* pBuf = trafficKey.data();
    BYTE* pBufEnd = pBuf + trafficKey.size();
    pair.clientKey = byteArray(pBuf, pBuf + 16);
    pBuf += 16;
    pair.serverKey = byteArray(pBuf, pBuf + 16);
    pBuf += 16;
    pair.clientNonce = byteArray(pBuf, pBuf + 12);
    pBuf += 12;
    pair.serverNonce = byteArray(pBuf, pBufEnd);
    return rc;
}

bool MMTLSClient::verifyEcdsa(const byteArray& data) {
    bool bVerify = false;
    int rc = 0;
    byteArray digest;
    rc = handshakeHasher->Sum(digest);
    if (rc < 0)
        return false;
    byteArray dataHash(SHA256_DIGEST_LENGTH, 0);
    SHA256_CTX sha256;
    rc = SHA256_Init(&sha256);
    rc = SHA256_Update(&sha256, digest.data(), digest.size());
    rc = SHA256_Final(dataHash.data(), &sha256);
    bVerify = ECDSA_verify(0, dataHash.data(), (int)dataHash.size(), data.data(), (int)data.size(), ServerEcdh);
    return bVerify;
}

byteArray MMTLSClient::hkdfExpand(const std::string& prefix, HandshakeHasher* const hash) {
    byteArray result(prefix.begin(), prefix.end());
    if (hash != nullptr) {
        byteArray hashSum;
        int rc = handshakeHasher->Sum(hashSum);
        if (rc >= 0)
            result.insert(result.end(), hashSum.begin(), hashSum.end());
    }
    return result;
}

byteArray MMTLSClient::hmac(const byteArray& k, const byteArray& d) {
    byteArray result(SHA256_DIGEST_LENGTH, 0);
    HMAC_CTX* ctx = HMAC_CTX_new();
    unsigned outlen = 0, ret = 0;
    ret = HMAC_Init_ex(ctx, k.data(), (unsigned)k.size(), EVP_sha256(), NULL);
    ret = HMAC_Update(ctx, d.data(), d.size());
    ret = HMAC_Final(ctx, result.data(), &outlen);
    HMAC_CTX_free(ctx);
    return result;
}


int MMTLSClient::genKeyPairs() {
    int Ret = 0;
    EC_KEY* ec_key = NULL;      //椭圆曲线的参数、私钥和公钥都保存在这个结构中。
    // curve in py: NIST256p
    ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key)
    {
        Ret = -1;
        return Ret;
    }
    Ret = EC_KEY_generate_key(ec_key);
    publicEcdh = ec_key;
    if (!Ret) {
        Ret = -1;
        return Ret;
    }
    ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key)
    {
        Ret = -1;
        return Ret;
    }
    Ret = EC_KEY_generate_key(ec_key);
    if (!Ret) {
        Ret = -1;
        return Ret;
    }
    verifyEcdh = ec_key;
    return Ret;
}