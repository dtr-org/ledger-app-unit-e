// Copyright (c) 2018 The Unit-e developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! \file cx.c
//! \brief A reimplementation of the Ledger Nano S cryptographic functions
//!        using OpenSSL
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>

#include <assert.h>
#include <string.h>

#include "os.h"
#include "cx.h"


#define ABORT(text, ...) do { \
    fprintf(stderr, "ERROR: " text "\n", ##__VA_ARGS__); \
    fprintf(stderr, "\tat %s, line %d\n", __FILE__, __LINE__) ; \
    exit(-1); \
} while(0)

int cx_sha256_init(cx_sha256_t *hash) {
    memset(hash, 0, sizeof(*hash));
    hash->header.algo = CX_SHA256;
    SHA256_Init(&hash->header.sha256_context);
    return 1;
}

int cx_ripemd160_init(cx_ripemd160_t *hash) {
    memset(hash, 0, sizeof(*hash));
    hash->header.algo = CX_RIPEMD160;
    RIPEMD160_Init(&hash->header.ripemd_context);
    return 1;
}

int cx_hash(
    cx_hash_t *hash, int mode, const unsigned char *in, unsigned int len,
    unsigned char *out
) {
    switch (hash->algo) {
        case CX_SHA256:
            SHA256_Update(&hash->sha256_context, in, len);
            break;
        case CX_RIPEMD160:
            RIPEMD160_Update(&hash->ripemd_context, in, len);
            break;
        default:
            ABORT("Invalid hash alforithm: %d", hash->algo);
    }

    if (mode == CX_LAST) {
        switch (hash->algo) {
            case CX_SHA256:
                SHA256_Final(out, &hash->sha256_context);
                break;
            case CX_RIPEMD160:
                RIPEMD160_Final(out, &hash->ripemd_context);
                break;
        }
    }
    return 1;
}

int cx_hmac_sha256(const unsigned char WIDE *key PLENGTH(key_len),
                           unsigned int key_len,
                           const unsigned char WIDE *in PLENGTH(len),
                           unsigned int len,
                           unsigned char *mac PLENGTH(mac_len) /*,
                           unsigned int mac_len */) {
    unsigned int md_len;
    unsigned char* out = HMAC(EVP_sha256(), key, key_len, in, len, mac, &md_len);
    if (!out) {
        ABORT("HMAC failed!");
    }
    return 1;
}

unsigned char cx_rng_u8(void) {
    unsigned char result;
    if (!RAND_bytes(&result, 1)) {
        ABORT("RAND_bytes failed");
    }

    return result;
}

unsigned char *cx_rng(unsigned char *buffer, unsigned int len) {
    if (!RAND_bytes(buffer, len)) {
        ABORT("RAND_bytes(%d) failed", len);
    }

    return buffer;
}

int cx_ecfp_init_private_key(
    cx_curve_t curve, const unsigned char *rawkey, unsigned int key_len,
    cx_ecfp_private_key_t *pvkey
) {
    assert(curve == CX_CURVE_SECP256K1);

    pvkey->curve = curve;
    pvkey->d_len = key_len;
    memcpy(pvkey->d, rawkey, key_len);
    return 1;
}

int cx_ecfp_generate_pair(
    cx_curve_t curve, cx_ecfp_public_key_t *pubkey,
    cx_ecfp_private_key_t *privkey, int keepprivate
) {
    assert(privkey->curve == CX_CURVE_SECP256K1);
    assert(privkey->d_len != 0);
    assert(keepprivate);

    BIGNUM *priv = BN_bin2bn(privkey->d, privkey->d_len, NULL);
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *pub = EC_POINT_new(group);

    EC_KEY_set_private_key(key, priv);
    if (!EC_POINT_mul(group, pub, priv, NULL, NULL, NULL)) {
        ABORT("Elliptic curve multiplication failed!\n");
    }

    pubkey->curve = privkey->curve;
    pubkey->W_len = 65;

    BIGNUM *pub_bn = EC_POINT_point2bn(group, pub, POINT_CONVERSION_UNCOMPRESSED, NULL, NULL);
    BN_bn2bin(pub_bn, pubkey->W);

    BN_free(pub_bn);
    EC_POINT_free(pub);
    EC_KEY_free(key);
    BN_free(priv);

    return 1;
}

int cx_ecdsa_sign(
    const cx_ecfp_private_key_t *pvkey, int mode, cx_md_t hashID,
    const unsigned char *hash, unsigned int hash_len, unsigned char *sig,
    unsigned int *info
) {
    assert(hashID == CX_SHA256);

    BIGNUM *priv = BN_bin2bn(pvkey->d, pvkey->d_len, NULL);
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *pub = EC_POINT_new(group);
    EC_KEY_set_private_key(key, priv);
    if (!EC_POINT_mul(group, pub, priv, NULL, NULL, NULL)) {
        ABORT("Elliptic curve multiplication failed!\n");
    }
    EC_KEY_set_public_key(key, pub);

    ECDSA_SIG *esig = ECDSA_do_sign(hash, hash_len, key);
    int result =  i2d_ECDSA_SIG(esig, &sig);
    
    ECDSA_SIG_free(esig);
    EC_POINT_free(pub);
    EC_KEY_free(key);
    BN_free(priv);

    return result;
}

int cx_ecdsa_verify(const cx_ecfp_public_key_t WIDE *pukey PLENGTH(
                                scc__cx_scc_struct_size_ecfp_pubkey__pukey),
                            int mode, cx_md_t hashID,
                            const unsigned char WIDE *hash PLENGTH(hash_len),
                            unsigned int hash_len,
                            const unsigned char WIDE *sig PLENGTH(sig_len),
                            unsigned int sig_len) {
    assert(hashID == CX_SHA256);

    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    const EC_GROUP *group = EC_KEY_get0_group(key);

    BIGNUM *bn_pub = BN_bin2bn(pukey->W, pukey->W_len, NULL);
    EC_POINT *pub = EC_POINT_bn2point(group, bn_pub, NULL, NULL);
    if (!pub) {
        ABORT("Cannot convert bignum to point!\n");
    }

    EC_KEY_set_public_key(key, pub);

    int result = ECDSA_verify(0, hash, hash_len, sig, sig_len, key);
    if (result == -1) {
        ABORT("ECDSA_verify failed!\n");
    }

    EC_POINT_free(pub);
    BN_free(bn_pub);
    EC_KEY_free(key);

    return result;
}
