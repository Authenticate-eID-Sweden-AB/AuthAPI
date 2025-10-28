#include "autheid_utils.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <cstring>

namespace autheid
{

namespace {

const int kNID = NID_secp256k1;

EC_KEY* createECKey()
{
   EC_KEY *key = EC_KEY_new_by_curve_name(kNID);
   if (!key) return nullptr;
   EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);
   return key;
}

}

PrivateKey generatePrivateKey()
{
   PrivateKey result(kPrivateKeySize);
   RAND_bytes(result.data(), kPrivateKeySize);
   return result;
}

PublicKey getPublicKey(const PrivateKey &privateKey)
{
   try {
      EC_KEY *key = createECKey();
      if (!key) return {};

      BIGNUM *priv_bn = BN_bin2bn(privateKey.data(), privateKey.size(), nullptr);
      if (!priv_bn) {
         EC_KEY_free(key);
         return {};
      }

      EC_KEY_set_private_key(key, priv_bn);

      const EC_GROUP *group = EC_KEY_get0_group(key);
      EC_POINT *pub_point = EC_POINT_new(group);
      EC_POINT_mul(group, pub_point, priv_bn, nullptr, nullptr, nullptr);
      EC_KEY_set_public_key(key, pub_point);

      unsigned char pub_buf[33];
      size_t pub_len = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_COMPRESSED,
                                          pub_buf, sizeof(pub_buf), nullptr);

      PublicKey result(pub_buf, pub_buf + pub_len);

      BN_clear_free(priv_bn);
      EC_POINT_free(pub_point);
      EC_KEY_free(key);

      if (result.size() != kPublicKeySize) {
         return {};
      }

      return result;
   } catch (...) {
      return {};
   }
}

static Bytes hkdf(const Bytes &ikm, const Bytes &salt, const Bytes &info, size_t outLen)
{
   Bytes result(outLen);
   EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
   if (!pctx) return {};

   if (EVP_PKEY_derive_init(pctx) <= 0) {
      EVP_PKEY_CTX_free(pctx);
      return {};
   }

   if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
      EVP_PKEY_CTX_free(pctx);
      return {};
   }

   if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt.size()) <= 0) {
      EVP_PKEY_CTX_free(pctx);
      return {};
   }

   if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), ikm.size()) <= 0) {
      EVP_PKEY_CTX_free(pctx);
      return {};
   }

   if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), info.size()) <= 0) {
      EVP_PKEY_CTX_free(pctx);
      return {};
   }

   size_t outlen = outLen;
   if (EVP_PKEY_derive(pctx, result.data(), &outlen) <= 0) {
      EVP_PKEY_CTX_free(pctx);
      return {};
   }

   EVP_PKEY_CTX_free(pctx);
   return result;
}

Bytes encryptData(const void *data, size_t dataSize, const PublicKey &publicKey)
{
   try {
      EC_KEY *their_key = createECKey();
      if (!their_key) return {};

      const EC_GROUP *group = EC_KEY_get0_group(their_key);
      EC_POINT *their_point = EC_POINT_new(group);
      if (!EC_POINT_oct2point(group, their_point, publicKey.data(), publicKey.size(), nullptr)) {
         EC_POINT_free(their_point);
         EC_KEY_free(their_key);
         return {};
      }

      EC_KEY_set_public_key(their_key, their_point);

      EC_KEY *my_key = createECKey();
      if (!EC_KEY_generate_key(my_key)) {
         EC_POINT_free(their_point);
         EC_KEY_free(their_key);
         EC_KEY_free(my_key);
         return {};
      }

      unsigned char shared_secret[32];
      int secret_len = ECDH_compute_key(shared_secret, 32, their_point, my_key, nullptr);
      if (secret_len != 32) {
         EC_POINT_free(their_point);
         EC_KEY_free(their_key);
         EC_KEY_free(my_key);
         return {};
      }

      Bytes shared(shared_secret, shared_secret + 32);
      Bytes salt;
      Bytes info;
      Bytes keys = hkdf(shared, salt, info, 32 + 20);
      if (keys.size() != 52) {
         EC_POINT_free(their_point);
         EC_KEY_free(their_key);
         EC_KEY_free(my_key);
         return {};
      }

      Bytes enc_key(keys.begin(), keys.begin() + 32);
      Bytes mac_key(keys.begin() + 32, keys.end());

      const EC_POINT *my_pub = EC_KEY_get0_public_key(my_key);
      unsigned char pub_buf[33];
      size_t pub_len = EC_POINT_point2oct(group, my_pub, POINT_CONVERSION_COMPRESSED,
                                          pub_buf, sizeof(pub_buf), nullptr);

      Bytes nonce(8);
      RAND_bytes(nonce.data(), 8);

      EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
      EVP_EncryptInit_ex(ctx, EVP_chacha20(), nullptr, enc_key.data(), nonce.data());

      Bytes ciphertext(dataSize);
      int len = 0;
      EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (const unsigned char*)data, dataSize);
      EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
      EVP_CIPHER_CTX_free(ctx);

      Bytes mac_data;
      mac_data.insert(mac_data.end(), pub_buf, pub_buf + pub_len);
      mac_data.insert(mac_data.end(), nonce.begin(), nonce.end());
      mac_data.insert(mac_data.end(), ciphertext.begin(), ciphertext.end());

      unsigned char mac[SHA256_DIGEST_LENGTH];
      unsigned int mac_len = 0;
      HMAC(EVP_sha256(), mac_key.data(), mac_key.size(), mac_data.data(), mac_data.size(), mac, &mac_len);

      Bytes result;
      result.insert(result.end(), pub_buf, pub_buf + pub_len);
      result.insert(result.end(), nonce.begin(), nonce.end());
      result.insert(result.end(), mac, mac + 20);
      result.insert(result.end(), ciphertext.begin(), ciphertext.end());

      EC_POINT_free(their_point);
      EC_KEY_free(their_key);
      EC_KEY_free(my_key);

      return result;
   } catch (...) {
      return {};
   }
}

SecureBytes decryptData(const void *data, size_t dataSize, const PrivateKey &privateKey)
{
   try {
      if (dataSize < 33 + 8 + 20) return {};

      const unsigned char *ptr = (const unsigned char*)data;
      
      Bytes their_pub(ptr, ptr + 33);
      ptr += 33;
      
      Bytes nonce(ptr, ptr + 8);
      ptr += 8;
      
      Bytes their_mac(ptr, ptr + 20);
      ptr += 20;
      
      size_t ciphertext_len = dataSize - (33 + 8 + 20);
      Bytes ciphertext(ptr, ptr + ciphertext_len);

      EC_KEY *my_key = createECKey();
      if (!my_key) return {};

      BIGNUM *priv_bn = BN_bin2bn(privateKey.data(), privateKey.size(), nullptr);
      if (!priv_bn) {
         EC_KEY_free(my_key);
         return {};
      }

      EC_KEY_set_private_key(my_key, priv_bn);

      const EC_GROUP *group = EC_KEY_get0_group(my_key);
      EC_POINT *pub_point = EC_POINT_new(group);
      EC_POINT_mul(group, pub_point, priv_bn, nullptr, nullptr, nullptr);
      EC_KEY_set_public_key(my_key, pub_point);

      EC_POINT *their_point = EC_POINT_new(group);
      if (!EC_POINT_oct2point(group, their_point, their_pub.data(), their_pub.size(), nullptr)) {
         BN_clear_free(priv_bn);
         EC_POINT_free(pub_point);
         EC_POINT_free(their_point);
         EC_KEY_free(my_key);
         return {};
      }

      unsigned char shared_secret[32];
      int secret_len = ECDH_compute_key(shared_secret, 32, their_point, my_key, nullptr);
      if (secret_len != 32) {
         BN_clear_free(priv_bn);
         EC_POINT_free(pub_point);
         EC_POINT_free(their_point);
         EC_KEY_free(my_key);
         return {};
      }

      Bytes shared(shared_secret, shared_secret + 32);
      Bytes salt;
      Bytes info;
      Bytes keys = hkdf(shared, salt, info, 32 + 20);
      if (keys.size() != 52) {
         BN_clear_free(priv_bn);
         EC_POINT_free(pub_point);
         EC_POINT_free(their_point);
         EC_KEY_free(my_key);
         return {};
      }

      Bytes enc_key(keys.begin(), keys.begin() + 32);
      Bytes mac_key(keys.begin() + 32, keys.end());

      Bytes mac_data;
      mac_data.insert(mac_data.end(), their_pub.begin(), their_pub.end());
      mac_data.insert(mac_data.end(), nonce.begin(), nonce.end());
      mac_data.insert(mac_data.end(), ciphertext.begin(), ciphertext.end());

      unsigned char mac[SHA256_DIGEST_LENGTH];
      unsigned int mac_len = 0;
      HMAC(EVP_sha256(), mac_key.data(), mac_key.size(), mac_data.data(), mac_data.size(), mac, &mac_len);

      if (std::memcmp(mac, their_mac.data(), 20) != 0) {
         BN_clear_free(priv_bn);
         EC_POINT_free(pub_point);
         EC_POINT_free(their_point);
         EC_KEY_free(my_key);
         return {};
      }

      EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
      EVP_DecryptInit_ex(ctx, EVP_chacha20(), nullptr, enc_key.data(), nonce.data());

      SecureBytes plaintext(ciphertext_len);
      int len = 0;
      EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext_len);
      plaintext.resize(len);
      EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
      EVP_CIPHER_CTX_free(ctx);

      BN_clear_free(priv_bn);
      EC_POINT_free(pub_point);
      EC_POINT_free(their_point);
      EC_KEY_free(my_key);

      return plaintext;
   } catch (...) {
      return {};
   }
}

Bytes signData(const void *data, size_t dataSize, const PrivateKey &privateKey, bool derFormat)
{
   try {
      EC_KEY *key = createECKey();
      if (!key) return {};

      BIGNUM *priv_bn = BN_bin2bn(privateKey.data(), privateKey.size(), nullptr);
      if (!priv_bn) {
         EC_KEY_free(key);
         return {};
      }

      EC_KEY_set_private_key(key, priv_bn);

      const EC_GROUP *group = EC_KEY_get0_group(key);
      EC_POINT *pub_point = EC_POINT_new(group);
      EC_POINT_mul(group, pub_point, priv_bn, nullptr, nullptr, nullptr);
      EC_KEY_set_public_key(key, pub_point);

      unsigned char hash[SHA256_DIGEST_LENGTH];
      SHA256((const unsigned char*)data, dataSize, hash);

      unsigned char sig_buf[256];
      unsigned int sig_len = 0;
      ECDSA_sign(0, hash, SHA256_DIGEST_LENGTH, sig_buf, &sig_len, key);

      Bytes signature;
      if (derFormat) {
         signature.assign(sig_buf, sig_buf + sig_len);
      } else {
         const unsigned char *sig_ptr = sig_buf;
         ECDSA_SIG *sig = d2i_ECDSA_SIG(nullptr, &sig_ptr, sig_len);
         if (!sig) {
            BN_clear_free(priv_bn);
            EC_POINT_free(pub_point);
            EC_KEY_free(key);
            return {};
         }

         const BIGNUM *r = nullptr;
         const BIGNUM *s = nullptr;
         ECDSA_SIG_get0(sig, &r, &s);

         unsigned char r_buf[32] = {0};
         unsigned char s_buf[32] = {0};
         BN_bn2bin(r, r_buf + 32 - BN_num_bytes(r));
         BN_bn2bin(s, s_buf + 32 - BN_num_bytes(s));

         signature.assign(r_buf, r_buf + 32);
         signature.insert(signature.end(), s_buf, s_buf + 32);

         ECDSA_SIG_free(sig);
      }

      BN_clear_free(priv_bn);
      EC_POINT_free(pub_point);
      EC_KEY_free(key);

      return signature;
   } catch (...) {
      return {};
   }
}

bool verifyData(const void *data, size_t dataSize, const void *sign, size_t signSize,
                const PublicKey &publicKey, bool derFormat)
{
   try {
      EC_KEY *key = createECKey();
      if (!key) return false;

      const EC_GROUP *group = EC_KEY_get0_group(key);
      EC_POINT *pub_point = EC_POINT_new(group);
      if (!EC_POINT_oct2point(group, pub_point, publicKey.data(), publicKey.size(), nullptr)) {
         EC_POINT_free(pub_point);
         EC_KEY_free(key);
         return false;
      }

      EC_KEY_set_public_key(key, pub_point);

      unsigned char hash[SHA256_DIGEST_LENGTH];
      SHA256((const unsigned char*)data, dataSize, hash);

      bool result = false;

      if (derFormat) {
         result = (ECDSA_verify(0, hash, SHA256_DIGEST_LENGTH,
                               (const unsigned char*)sign, signSize, key) == 1);
      } else {
         if (signSize != 64) {
            EC_POINT_free(pub_point);
            EC_KEY_free(key);
            return false;
         }

         const unsigned char *ptr = (const unsigned char*)sign;
         BIGNUM *r = BN_bin2bn(ptr, 32, nullptr);
         BIGNUM *s = BN_bin2bn(ptr + 32, 32, nullptr);

         ECDSA_SIG *sig = ECDSA_SIG_new();
         ECDSA_SIG_set0(sig, r, s);

         unsigned char der_buf[256];
         unsigned char *der_ptr = der_buf;
         int der_len = i2d_ECDSA_SIG(sig, &der_ptr);

         result = (ECDSA_verify(0, hash, SHA256_DIGEST_LENGTH, der_buf, der_len, key) == 1);

         ECDSA_SIG_free(sig);
      }

      EC_POINT_free(pub_point);
      EC_KEY_free(key);

      return result;
   } catch (...) {
      return false;
   }
}

}
