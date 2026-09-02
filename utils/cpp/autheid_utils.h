#pragma once
#include <cstdint>
#include <vector>
#include <string>

#ifdef BUILD_BOTAN
#if !defined(AUTHEID_BOTAN_AMALGAMATION)
#include <botan/secmem.h>
#else
#include <botan_all.h>
#endif
#else
#include <Utils/Cryptography.h>
#endif

namespace autheid
{
// secp256k1 secret key
constexpr size_t kPrivateKeySize = 32;
// secp256k1 EC point (compressed)
constexpr size_t kPublicKeySize = 33;

using Bytes = std::vector<uint8_t>;
#ifdef BUILD_BOTAN
using SecureBytes = Botan::secure_vector<uint8_t>;
using PublicKey = Bytes;
using PrivateKey = SecureBytes;
#else
using SecureBytes = SecureBinaryData;
using PrivateKey = SecureBytes;

class PublicKey : public SecureBinaryData
{
public:
   PublicKey() : SecureBinaryData() {};
   PublicKey(const SecureBinaryData& data) : SecureBinaryData(data) {};
   PublicKey(const Bytes& data) : SecureBinaryData(data.data(), data.size()) {};

   SecureBinaryData deriveSharedSecret();
};
#endif


PrivateKey generatePrivateKey();
PublicKey getPublicKey(const PrivateKey &privateKey);

SecureBytes encryptData(const void *data, size_t dataSize, PublicKey);

// Returns empty data if decrypt failed
SecureBytes decryptData(const void *data, size_t dataSize, const PrivateKey &privateKey);

Bytes signData(const void *data, size_t dataSize, const PrivateKey &privateKey, bool derFormat = false);

bool verifyData(const void *data, size_t dataSize, const void *sign, size_t signSize
   , const PublicKey &publicKey, bool derFormat = false);

} // namespace autheid
