#pragma once
#include <cstdint>
#include <vector>
#include <string>

namespace autheid
{

constexpr size_t kPrivateKeySize = 32;

constexpr size_t kPublicKeySize = 33;

using Bytes = std::vector<uint8_t>;
using SecureBytes = std::vector<uint8_t>;

using PublicKey = Bytes;
using PrivateKey = SecureBytes;

PrivateKey generatePrivateKey();
PublicKey getPublicKey(const PrivateKey &privateKey);

Bytes encryptData(const void *data, size_t dataSize, const PublicKey &publicKey);

SecureBytes decryptData(const void *data, size_t dataSize, const PrivateKey &privateKey);

Bytes signData(const void *data, size_t dataSize, const PrivateKey &privateKey, bool derFormat = false);

bool verifyData(const void *data, size_t dataSize, const void *sign, size_t signSize
   , const PublicKey &publicKey, bool derFormat = false);

}
