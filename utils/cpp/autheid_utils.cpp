#include "autheid_utils.h"

#ifdef BUILD_BOTAN
#if !defined(AUTHEID_BOTAN_AMALGAMATION)
#include <botan/auto_rng.h>
#include <botan/bigint.h>
#include <botan/ecdh.h>
#include <botan/ecies.h>
#include <botan/ecdsa.h>
#endif
#else
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <spdlog/spdlog.h>
#include <Utils/Cryptography.h>
#endif
#include <iostream>


namespace  {
   const auto kDomain = "secp256k1";
   const auto kSignAlg = "EMSA1(SHA-256)";

#ifdef BUILD_BOTAN
   // Use stream cipher and compressed point to get smaller encrypted size
   const Botan::ECIES_System_Params kEciesParams(Botan::EC_Group{ kDomain },
      "KDF2(SHA-256)", "ChaCha(20)", 32, "HMAC(SHA-256)", 20,
      Botan::PointGFp::COMPRESSED, Botan::ECIES_Flags::NONE);
#endif
} // namespace

namespace autheid {
   PrivateKey generatePrivateKey()
   {
#ifdef BUILD_BOTAN
      Botan::AutoSeeded_RNG rnd;
      return rnd.random_vec(kPrivateKeySize);
#else
      return Cryptography::PRNG::generateRandomStrong(kPrivateKeySize);
#endif
   }

   PublicKey getPublicKey(const PrivateKey& privateKey)
   {
#ifdef BUILD_BOTAN
      try {
         Botan::AutoSeeded_RNG rnd;

         Botan::BigInt privateKeyValue;
         privateKeyValue.binary_decode(privateKey);
         Botan::ECDH_PrivateKey privateKeyEC(rnd, Botan::EC_Group{ kDomain }, privateKeyValue);
         privateKeyValue.clear();

         const auto publicKey = privateKeyEC.public_point().encode(Botan::PointGFp::COMPRESSED);
         if (publicKey.size() != kPublicKeySize) {
            return {};
         }
         return publicKey;
      } catch (...) {
         return {};
      }
#else
      return Cryptography::ECDSA::computePublicKey(privateKey, true);
#endif
   }

   SecureBytes encryptData(const void* data, size_t dataSize, PublicKey publicKey)
   {
#ifdef BUILD_BOTAN
      try {
         Botan::AutoSeeded_RNG rng;
         auto publicKeyDecoded = Botan::EC_Group{ kDomain }.OS2ECP(publicKey);
         Botan::ECIES_Encryptor encrypt(rng, kEciesParams);
         encrypt.set_other_key(publicKeyDecoded);

         const auto& result = encrypt.encrypt(static_cast<const uint8_t*>(data), dataSize, rng);
         return result;
      } catch (...) {
         return {};
      }
#else
      const auto& iv = Cryptography::PRNG::generateRandomStrong(16);
      const auto& key = publicKey.deriveSharedSecret();
      auto result = iv;
      result.append(Cryptography::Encryption::AES::encryptCBC(SecureBinaryData((uint8_t*)data, dataSize)
         , key, iv));
      return result;
#endif
   }

   SecureBytes decryptData(const void* data, size_t dataSize, const PrivateKey& privateKey)
   {
#ifdef BUILD_BOTAN
      try {
         Botan::AutoSeeded_RNG rng;

         Botan::BigInt privateKeyValue;
         privateKeyValue.binary_decode(privateKey);
         Botan::ECDH_PrivateKey privateKeyDecoded(rng, Botan::EC_Group{ kDomain }, privateKeyValue);
         privateKeyValue.clear();

         Botan::ECIES_Decryptor decryptor(privateKeyDecoded, kEciesParams, rng);

         auto result = decryptor.decrypt(static_cast<const uint8_t*>(data), dataSize);
         return result;
      } catch (const Botan::Decoding_Error& e) {
         std::cerr << "botan exc: " << e.what() << "\n";
         return {};
      } catch (const std::exception& e) {
         std::cerr << "exc: " << e.what() << "\n";
         return {};
      }
#else
      const auto& iv = SecureBinaryData((const uint8_t*)data, 16);
      const auto& key = getPublicKey(privateKey).deriveSharedSecret();
      return Cryptography::Encryption::AES::decryptCBC(SecureBinaryData(
         (const uint8_t*)data + 16, dataSize - 16), key, iv);
#endif
   }

   Bytes signData(const void* data, size_t dataSize, const PrivateKey& privateKey, bool derFormat)
   {
      try {
#ifdef BUILD_BOTAN
         Botan::AutoSeeded_RNG rng;

         Botan::BigInt privateKeyValue;
         privateKeyValue.binary_decode(privateKey);
         Botan::ECDSA_PrivateKey privateKeyDecoded(rng, Botan::EC_Group{ kDomain }
            , privateKeyValue);
         // Clear data for security
         privateKeyValue.clear();

         Botan::PK_Signer signer(privateKeyDecoded, rng, kSignAlg, derFormat ? Botan::DER_SEQUENCE : Botan::IEEE_1363);
         signer.update(static_cast<const uint8_t*>(data), dataSize);
         Bytes signature = signer.signature(rng);
         return signature;
#else
         return Cryptography::ECDSA::signData(BinaryData{ (const uint8_t*)data
            , dataSize }, privateKey)
            .getDataVector();
#endif
      } catch (...) {
         return {};
      }
   }

   bool verifyData(const void* data, size_t dataSize, const void* sign, size_t signSize
      , const PublicKey& publicKey, bool derFormat)
   {
      try {
#ifdef BUILD_BOTAN
         const Botan::EC_Group domain(kDomain);
         auto publicKeyValue = domain.OS2ECP(publicKey);
         Botan::ECDSA_PublicKey publicKeyDecoded(domain, publicKeyValue);

         Botan::PK_Verifier verifier(publicKeyDecoded, kSignAlg, derFormat ? Botan::DER_SEQUENCE : Botan::IEEE_1363);
         verifier.update(static_cast<const uint8_t*>(data), dataSize);
         return verifier.check_signature(static_cast<const uint8_t*>(sign)
            , signSize);
#else
         return Cryptography::ECDSA::verifyData(BinaryData{ (const uint8_t*)data
            , dataSize }, BinaryData{ (const uint8_t*)sign, signSize }, publicKey);
#endif
      } catch (...) {
         return false;
      }
   }

   SecureBinaryData PublicKey::deriveSharedSecret()
   {
      SecureBinaryData result(32);
      Cryptography::Hash::getHash256(*this, result.getPtr());
      return result;
   }
}
