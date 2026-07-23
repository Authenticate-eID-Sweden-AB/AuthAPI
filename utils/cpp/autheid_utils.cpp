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
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <Utils/Cryptography.h>
#endif
#include <iostream>


namespace  {
   const auto kDomain = "secp256k1";
   const auto kSignAlg = "EMSA1(SHA-256)";

#ifdef BUILD_BOTAN
   // Use stream cipher and compressed point to get smaller encrypted size
   const Botan::ECIES_System_Params kEciesParams(kDomain,
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
      try {
#ifdef BUILD_BOTAN
         Botan::AutoSeeded_RNG rnd;

         Botan::BigInt privateKeyValue;
         privateKeyValue.binary_decode(privateKey);
         Botan::ECDH_PrivateKey privateKeyEC(rnd, kDomain, privateKeyValue);
         privateKeyValue.clear();

         const auto publicKey = privateKeyEC.public_point().encode(Botan::PointGFp::COMPRESSED);
         if (publicKey.size() != kPublicKeySize) {
            return {};
         }
         return publicKey;
#else
         return Cryptography::ECDSA::computePublicKey(privateKey, true);
#endif
      } catch (...) {
         return {};
      }
   }

   Bytes encryptData(const void* data, size_t dataSize, const PublicKey& publicKey)
   {
      try {
#ifdef BUILD_BOTAN
         Botan::AutoSeeded_RNG rng;
         auto publicKeyDecoded = kDomain.OS2ECP(publicKey);
         Botan::ECIES_Encryptor encrypt(rng, kEciesParams);
         encrypt.set_other_key(publicKeyDecoded);

         const auto& result = encrypt.encrypt(static_cast<const uint8_t*>(data), dataSize, rng);
         return result;
#else
         EVP_PKEY_CTX* ctx = NULL;
         EVP_PKEY* ephemeralKey = NULL;
         const unsigned char* pubKeyBytes = publicKey.getPtr();
         auto outEphemeralPubDer = (unsigned char*)OPENSSL_malloc(publicKey.getSize());
         const auto recvPubKey = d2i_PUBKEY(NULL, &pubKeyBytes, publicKey.getSize());
         size_t sharedSecretLen = 0;
         unsigned char keyAES[32];

         // 1. Generate Ephemeral EC Key on the same curve
         ctx = EVP_PKEY_CTX_new_from_pkey(NULL, recvPubKey, NULL);
         EVP_PKEY_keygen_init(ctx);
         EVP_PKEY_keygen(ctx, &ephemeralKey);
         EVP_PKEY_CTX_free(ctx);

         // 2. Export Ephemeral Public Key to DER (so receiver can read it later)
         const auto outEphemeralPubLen = i2d_PUBKEY(ephemeralKey, &outEphemeralPubDer);

         // 3. Set up ECDH Derivation
         ctx = EVP_PKEY_CTX_new(ephemeralKey, NULL);
         EVP_PKEY_derive_init(ctx);
         EVP_PKEY_derive_set_peer(ctx, recvPubKey);

         // Determine buffer size for shared secret and derive it
         EVP_PKEY_derive(ctx, NULL, &sharedSecretLen);
         auto sharedSecret = (unsigned char*)OPENSSL_malloc(sharedSecretLen);
         EVP_PKEY_derive(ctx, sharedSecret, &sharedSecretLen);
         EVP_PKEY_CTX_free(ctx);

         // 4. KDF Layer: Hash the shared secret to obtain a 256-bit AES key
         EVP_Q_digest(NULL, "SHA256", NULL, sharedSecret, sharedSecretLen, keyAES, NULL);
         OPENSSL_free(sharedSecret);

         // 5. Symmetric Cipher Layer: Encrypt plaintext with AES-256-GCM
         EVP_CIPHER_CTX* ctxCipher = EVP_CIPHER_CTX_new();
         const EVP_CIPHER* cipher = EVP_aes_256_gcm();

         unsigned char iv[12] = { 0 }; // Use a cryptographically secure random IV in production!
         Bytes result(dataSize + EVP_CIPHER_block_size(cipher));

         EVP_EncryptInit_ex(ctxCipher, cipher, NULL, keyAES, iv);

         int len = 0;
         EVP_EncryptUpdate(ctxCipher, result.data(), &len, (unsigned char*)data, dataSize);
         int finalLen = len;

         EVP_EncryptFinal_ex(ctxCipher, result.data() + len, &len);
         finalLen += len;
         if (result.size() > finalLen) {
            result.resize(finalLen);
         }
         EVP_CIPHER_CTX_free(ctxCipher);
         EVP_PKEY_free(ephemeralKey);
         OPENSSL_free(outEphemeralPubDer);   //maybe it should be passed upstream
         return result;
#endif
      } catch (...) {
         return {};
      }
   }

   SecureBytes decryptData(const void* data, size_t dataSize, const PrivateKey& privateKey)
   {
      try {
#ifdef BUILD_BOTAN
         Botan::AutoSeeded_RNG rng;

         Botan::BigInt privateKeyValue;
         privateKeyValue.binary_decode(privateKey);
         Botan::ECDH_PrivateKey privateKeyDecoded(rng, kDomain, privateKeyValue);
         privateKeyValue.clear();

         Botan::ECIES_Decryptor decryptor(privateKeyDecoded, kEciesParams, rng);

         auto result = decryptor.decrypt(static_cast<const uint8_t*>(data), dataSize);
         return result;
      } catch (const Botan::Decoding_Error& e) {
         std::cerr << "botan exc: " << e.what() << "\n";
         return {};
#else
         const unsigned char* privKeyBytes = privateKey.getPtr();
         const auto recvPrivKey = d2i_AutoPrivateKey(NULL, &privKeyBytes, privateKey.getSize());
         const auto publicKey = getPublicKey(privateKey);
         const unsigned char* pubKeyBytes = publicKey.getPtr();
         auto outEphemeralPubDer = (unsigned char*)OPENSSL_malloc(publicKey.getSize());
         const auto recvPubKey = d2i_PUBKEY(NULL, &pubKeyBytes, publicKey.getSize());
         EVP_PKEY_CTX* ctxPub = NULL;
         EVP_PKEY* ephemeralKey = NULL;
         ctxPub = EVP_PKEY_CTX_new_from_pkey(NULL, recvPubKey, NULL);
         EVP_PKEY_keygen_init(ctxPub);
         EVP_PKEY_keygen(ctxPub, &ephemeralKey);
         EVP_PKEY_CTX_free(ctxPub);

         // 1. Initialize the ECDH derivation context
         auto ctx = EVP_PKEY_CTX_new(recvPrivKey, NULL);
         EVP_PKEY_derive_init(ctx);
         EVP_PKEY_derive_set_peer(ctx, ephemeralKey);

         // 2. Determine the shared secret length buffer size and derive it
         unsigned char* sharedSecret;
         size_t secretLen = 0;
         EVP_PKEY_derive(ctx, NULL, &secretLen);
         sharedSecret = (unsigned char*)OPENSSL_malloc(secretLen);
         EVP_PKEY_derive(ctx, sharedSecret, &secretLen);

         // 3. Set up the Symmetric Decryption Context (AES-256-GCM / CBC)
         EVP_CIPHER_CTX* cipher_ctx = EVP_CIPHER_CTX_new();
         int outLen=0, finalLen=0;

         SecureBytes result(dataSize * 2);
         // Note: Use a Key Derivation Function (KDF) on shared_secret if the sender used one.
         EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_cbc(), NULL, sharedSecret, NULL);
         EVP_DecryptUpdate(cipher_ctx, (unsigned char*)result.getDataVector().data()
            , &outLen, (unsigned char*)data, dataSize);
         EVP_DecryptFinal_ex(cipher_ctx, (unsigned char*)result.getDataVector().data() + outLen
            , &finalLen);
         result.resize(finalLen);

         // Cleanup resources
         OPENSSL_clear_free(sharedSecret, secretLen);
         EVP_CIPHER_CTX_free(cipher_ctx);
         EVP_PKEY_CTX_free(ctx);
         OPENSSL_free(outEphemeralPubDer);
         return result;
#endif
      } catch (const std::exception& e) {
         std::cerr << "exc: " << e.what() << "\n";
         return {};
      }
   }

   Bytes signData(const void* data, size_t dataSize, const PrivateKey& privateKey, bool derFormat)
   {
      try {
#ifdef BUILD_BOTAN
         Botan::AutoSeeded_RNG rng;

         Botan::BigInt privateKeyValue;
         privateKeyValue.binary_decode(privateKey);
         Botan::ECDSA_PrivateKey privateKeyDecoded(rng, kDomain, privateKeyValue);
         // Clear data for security
         privateKeyValue.clear();

         Botan::PK_Signer signer(privateKeyDecoded, rng, kSignAlg, derFormat ? Botan::DER_SEQUENCE : Botan::IEEE_1363);
         signer.update(static_cast<const uint8_t*>(data), dataSize);
         Bytes signature = signer.signature(rng);
         return signature;
#else
         return Cryptography::ECDSA::signData(BinaryData{ (const uint8_t*)data
            , dataSize }, privateKey).getDataVector();
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
}
