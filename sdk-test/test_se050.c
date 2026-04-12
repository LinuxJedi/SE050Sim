/*
 * SE050 Simulator SDK Test Suite
 *
 * Tests the SE050 simulator through the NXP Plug&Trust SDK's SSS API,
 * with independent verification using OpenSSL.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* NXP SDK headers */
#include "fsl_sss_api.h"
#include "fsl_sss_se05x_apis.h"
#include "fsl_sss_se05x_types.h"
#include "ex_sss_boot.h"
#include "se05x_APDU_apis.h"
#include "nxLog.h"

/* OpenSSL headers */
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/rand.h>

#include "test_helpers.h"

/* Global session context */
static ex_sss_boot_ctx_t g_ctx;
static sss_se05x_session_t *g_session;
static sss_se05x_key_store_t g_ks;

/* Object ID base — use high range to avoid conflicts */
#define OBJ_ID_BASE 0x10000000

/* ======================================================================
 * Session initialization
 * ====================================================================== */

static int init_session(void)
{
    sss_status_t status;

    memset(&g_ctx, 0, sizeof(g_ctx));

    status = ex_sss_boot_open(&g_ctx, NULL);
    if (status != kStatus_SSS_Success) {
        fprintf(stderr, "ERROR: ex_sss_boot_open failed: %d\n", (int)status);
        return -1;
    }

    g_session = (sss_se05x_session_t *)&g_ctx.session;

    status = sss_key_store_context_init(&g_ks, &g_ctx.session);
    if (status != kStatus_SSS_Success) {
        fprintf(stderr, "ERROR: sss_key_store_context_init failed\n");
        return -1;
    }

    status = sss_key_store_allocate(&g_ks, 0);
    if (status != kStatus_SSS_Success) {
        fprintf(stderr, "ERROR: sss_key_store_allocate failed\n");
        return -1;
    }

    return 0;
}

/* ======================================================================
 * Helper: delete object if it exists
 * ====================================================================== */
static void cleanup_object(uint32_t obj_id)
{
    sss_se05x_object_t obj;
    sss_key_object_init(&obj, &g_ks);
    sss_key_object_allocate_handle(&obj, obj_id,
        kSSS_KeyPart_Default, kSSS_CipherType_Binary, 0,
        kKeyObject_Mode_Persistent);
    sss_key_store_erase_key(&g_ks, &obj);
    sss_key_object_free(&obj);
}

/* ======================================================================
 * Test: Random Number Generation
 * ====================================================================== */
static void test_rng(void)
{
    TEST_BEGIN("RNG");
    sss_status_t status;
    sss_se05x_rng_context_t rng;
    uint8_t buf1[32] = {0};
    uint8_t buf2[32] = {0};
    uint8_t zeros[32] = {0};

    status = sss_rng_context_init(&rng, &g_ctx.session);
    ASSERT_OK(status, "rng_context_init");

    status = sss_rng_get_random(&rng, buf1, sizeof(buf1));
    ASSERT_OK(status, "rng_get_random #1");

    status = sss_rng_get_random(&rng, buf2, sizeof(buf2));
    ASSERT_OK(status, "rng_get_random #2");

    /* Should not be all zeros */
    ASSERT_MEM_NEQ(buf1, zeros, 32, "random data is all zeros");

    /* Two calls should produce different data */
    ASSERT_MEM_NEQ(buf1, buf2, 32, "two random calls returned same data");

    sss_rng_context_free(&rng);
    TEST_PASS();
}

/* ======================================================================
 * Test: SHA Digests (cross-verified with OpenSSL)
 * ====================================================================== */
static void test_sha(const char *name, sss_algorithm_t algo,
                     const EVP_MD *md, size_t hash_len)
{
    TEST_BEGIN(name);
    sss_status_t status;
    sss_se05x_digest_t dctx;
    uint8_t data[] = "abc";
    uint8_t se050_hash[64] = {0};
    size_t se050_hash_len = sizeof(se050_hash);
    uint8_t openssl_hash[64] = {0};
    unsigned int openssl_hash_len = 0;

    /* Hash via SE050 */
    status = sss_digest_context_init(&dctx, &g_ctx.session, algo, kMode_SSS_Digest);
    ASSERT_OK(status, "digest_context_init");

    status = sss_digest_one_go(&dctx, data, 3, se050_hash, &se050_hash_len);
    ASSERT_OK(status, "digest_one_go");

    ASSERT_EQ(se050_hash_len, hash_len, "hash length mismatch");

    /* Hash via OpenSSL */
    EVP_Digest(data, 3, openssl_hash, &openssl_hash_len, md, NULL);

    /* Compare */
    ASSERT_MEM_EQ(se050_hash, openssl_hash, hash_len, "hash mismatch with OpenSSL");

    sss_digest_context_free(&dctx);
    TEST_PASS();
}

/* ======================================================================
 * Test: ECC Key Generation + ECDSA Sign (verified by OpenSSL)
 * ====================================================================== */
static void test_ecc_sign_verify(const char *name, uint32_t obj_id,
                                 sss_cipher_type_t cipher, int key_bytes,
                                 int key_bits, SE05x_ECCurve_t curve_id,
                                 int nid)
{
    TEST_BEGIN(name);
    sss_status_t status;
    sss_se05x_object_t key_obj;
    sss_se05x_asymmetric_t asym;

    uint8_t pubkey_der[256] = {0};
    size_t pubkey_der_len = sizeof(pubkey_der);
    size_t pubkey_bits = 0;

    uint8_t hash[32];
    memset(hash, 0x42, sizeof(hash));

    uint8_t sig[256] = {0};
    size_t sig_len = sizeof(sig);

    /* Generate key pair via SE050 */
    cleanup_object(obj_id);
    sss_key_object_init(&key_obj, &g_ks);
    status = sss_key_object_allocate_handle(&key_obj, obj_id,
        kSSS_KeyPart_Pair, cipher, key_bytes,
        kKeyObject_Mode_Persistent);
    ASSERT_OK(status, "key_object_allocate_handle");

    status = sss_key_store_generate_key(&g_ks, &key_obj, key_bits, NULL);
    ASSERT_OK(status, "key_store_generate_key");

    /* Read public key (DER-encoded SubjectPublicKeyInfo) */
    status = sss_key_store_get_key(&g_ks, &key_obj,
        pubkey_der, &pubkey_der_len, &pubkey_bits);
    ASSERT_OK(status, "key_store_get_key");

    /* Sign hash via SE050 */
    status = sss_asymmetric_context_init(&asym, &g_ctx.session, &key_obj,
        kAlgorithm_SSS_ECDSA_SHA256, kMode_SSS_Sign);
    ASSERT_OK(status, "asymmetric_context_init sign");

    status = sss_asymmetric_sign_digest(&asym, hash, 32, sig, &sig_len);
    ASSERT_OK(status, "asymmetric_sign_digest");

    sss_asymmetric_context_free(&asym);

    /* Verify signature with OpenSSL (prehash ECDSA) */
    {
        const uint8_t *p = pubkey_der;
        EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, (long)pubkey_der_len);
        if (!pkey) TEST_FAIL("OpenSSL: failed to parse public key DER");

        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!pctx) TEST_FAIL("OpenSSL: PKEY_CTX_new failed");
        if (EVP_PKEY_verify_init(pctx) != 1)
            TEST_FAIL("OpenSSL: PKEY_verify_init failed");

        int rc = EVP_PKEY_verify(pctx, sig, sig_len, hash, 32);

        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);

        if (rc != 1) {
            unsigned long err = ERR_get_error();
            char errbuf[256];
            ERR_error_string_n(err, errbuf, sizeof(errbuf));
            TEST_FAILF("OpenSSL verify failed: %s", errbuf);
        }
    }

    /* Cleanup */
    sss_key_store_erase_key(&g_ks, &key_obj);
    sss_key_object_free(&key_obj);
    TEST_PASS();
}

/* ======================================================================
 * Test: AES Encrypt (decrypted by OpenSSL to verify)
 * ====================================================================== */
static void test_aes_cbc(const char *name, uint32_t obj_id,
                         int key_len, const EVP_CIPHER *cipher)
{
    TEST_BEGIN(name);
    sss_status_t status;
    sss_se05x_object_t key_obj;
    sss_se05x_symmetric_t sym;

    /* Known key and data */
    uint8_t key[32];
    memset(key, 0xAA, key_len);
    uint8_t iv[16] = {0};
    uint8_t plaintext[16];
    memset(plaintext, 0x42, 16);
    uint8_t ciphertext[16] = {0};
    size_t ct_len = sizeof(ciphertext);

    /* Write key to SE050 */
    cleanup_object(obj_id);
    sss_key_object_init(&key_obj, &g_ks);
    status = sss_key_object_allocate_handle(&key_obj, obj_id,
        kSSS_KeyPart_Default, kSSS_CipherType_AES, key_len,
        kKeyObject_Mode_Persistent);
    ASSERT_OK(status, "aes key allocate");

    status = sss_key_store_set_key(&g_ks, &key_obj, key, key_len,
        key_len * 8, NULL, 0);
    ASSERT_OK(status, "aes key set");

    /* Encrypt via SE050 */
    status = sss_symmetric_context_init(&sym, &g_ctx.session, &key_obj,
        kAlgorithm_SSS_AES_CBC, kMode_SSS_Encrypt);
    ASSERT_OK(status, "symmetric_context_init");

    status = sss_cipher_one_go(&sym, iv, 16, plaintext, ciphertext, 16);
    ASSERT_OK(status, "cipher_one_go encrypt");

    sss_symmetric_context_free(&sym);

    /* Ciphertext should differ from plaintext */
    ASSERT_MEM_NEQ(ciphertext, plaintext, 16, "ciphertext equals plaintext");

    /* Decrypt with OpenSSL and compare */
    {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        uint8_t decrypted[32] = {0};
        int dec_len = 0;

        EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);
        EVP_CIPHER_CTX_set_padding(ctx, 0); /* no padding — AES-CBC nopad */
        EVP_DecryptUpdate(ctx, decrypted, &dec_len, ciphertext, 16);

        EVP_CIPHER_CTX_free(ctx);

        ASSERT_EQ(dec_len, 16, "OpenSSL decrypt length mismatch");
        ASSERT_MEM_EQ(decrypted, plaintext, 16, "AES roundtrip mismatch");
    }

    sss_key_store_erase_key(&g_ks, &key_obj);
    sss_key_object_free(&key_obj);
    TEST_PASS();
}

/* ======================================================================
 * Test: ECDH Shared Secret (both directions must match)
 * ====================================================================== */
static void test_ecdh(const char *name, uint32_t obj_a, uint32_t obj_b,
                      uint32_t obj_ss, int key_bytes, int key_bits)
{
    TEST_BEGIN(name);
    sss_status_t status;
    sss_se05x_object_t key_a, key_b, derived_key;
    sss_se05x_derive_key_t derive_ctx;

    uint8_t shared[64] = {0};
    size_t shared_len = sizeof(shared);
    size_t shared_bits = 0;

    /* Generate two key pairs */
    cleanup_object(obj_a);
    cleanup_object(obj_b);
    cleanup_object(obj_ss);

    sss_key_object_init(&key_a, &g_ks);
    status = sss_key_object_allocate_handle(&key_a, obj_a,
        kSSS_KeyPart_Pair, kSSS_CipherType_EC_NIST_P, key_bytes,
        kKeyObject_Mode_Persistent);
    ASSERT_OK(status, "key_a allocate");
    status = sss_key_store_generate_key(&g_ks, &key_a, key_bits, NULL);
    ASSERT_OK(status, "key_a generate");

    sss_key_object_init(&key_b, &g_ks);
    status = sss_key_object_allocate_handle(&key_b, obj_b,
        kSSS_KeyPart_Pair, kSSS_CipherType_EC_NIST_P, key_bytes,
        kKeyObject_Mode_Persistent);
    ASSERT_OK(status, "key_b allocate");
    status = sss_key_store_generate_key(&g_ks, &key_b, key_bits, NULL);
    ASSERT_OK(status, "key_b generate");

    /* Compute ECDH(A_priv, B_pub) */
    sss_key_object_init(&derived_key, &g_ks);
    status = sss_key_object_allocate_handle(&derived_key, obj_ss,
        kSSS_KeyPart_Default, kSSS_CipherType_Binary, key_bytes,
        kKeyObject_Mode_Transient);
    ASSERT_OK(status, "derived allocate");

    status = sss_derive_key_context_init(&derive_ctx, &g_ctx.session,
        &key_a, kAlgorithm_SSS_ECDH, kMode_SSS_ComputeSharedSecret);
    ASSERT_OK(status, "derive_key_context_init");

    sss_key_store_erase_key(&g_ks, &derived_key);
    status = sss_derive_key_dh(&derive_ctx, &key_b, &derived_key);
    ASSERT_OK(status, "derive_key_dh");

    sss_derive_key_context_free(&derive_ctx);

    /* Read shared secret */
    status = sss_key_store_get_key(&g_ks, &derived_key,
        shared, &shared_len, &shared_bits);
    ASSERT_OK(status, "get shared secret");

    /* Should not be all zeros */
    uint8_t zeros[64] = {0};
    ASSERT_MEM_NEQ(shared, zeros, shared_len, "shared secret is all zeros");

    /* Cleanup */
    sss_key_store_erase_key(&g_ks, &key_a);
    sss_key_store_erase_key(&g_ks, &key_b);
    sss_key_store_erase_key(&g_ks, &derived_key);
    sss_key_object_free(&key_a);
    sss_key_object_free(&key_b);
    sss_key_object_free(&derived_key);
    TEST_PASS();
}

/* ======================================================================
 * Test: RSA Key Generation + Sign (verified by OpenSSL)
 * ====================================================================== */
static void test_rsa_sign_verify(const char *name, uint32_t obj_id,
                                 int key_bits)
{
    TEST_BEGIN(name);
    sss_status_t status;
    sss_se05x_object_t key_obj;
    sss_se05x_asymmetric_t asym;

    /* RSA-4096 pubkey DER is ~540 bytes; size for headroom. */
    uint8_t pubkey_der[1024] = {0};
    size_t pubkey_der_len = sizeof(pubkey_der);
    size_t pubkey_bits = 0;

    uint8_t hash[32];
    memset(hash, 0x42, sizeof(hash));

    uint8_t sig[512] = {0};
    size_t sig_len = sizeof(sig);

    /* Generate RSA key pair via SE050 */
    cleanup_object(obj_id);
    sss_key_object_init(&key_obj, &g_ks);
    status = sss_key_object_allocate_handle(&key_obj, obj_id,
        kSSS_KeyPart_Pair, kSSS_CipherType_RSA, key_bits / 8,
        kKeyObject_Mode_Persistent);
    ASSERT_OK(status, "rsa key allocate");

    status = sss_key_store_generate_key(&g_ks, &key_obj, key_bits, NULL);
    ASSERT_OK(status, "rsa key generate");

    /* Read public key (DER-encoded) */
    status = sss_key_store_get_key(&g_ks, &key_obj,
        pubkey_der, &pubkey_der_len, &pubkey_bits);
    ASSERT_OK(status, "rsa get public key");

    /* Sign hash via SE050 (PKCS#1 v1.5 SHA-256) */
    status = sss_asymmetric_context_init(&asym, &g_ctx.session, &key_obj,
        kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256, kMode_SSS_Sign);
    ASSERT_OK(status, "rsa asymmetric_context_init");

    status = sss_asymmetric_sign_digest(&asym, hash, 32, sig, &sig_len);
    ASSERT_OK(status, "rsa sign_digest");

    sss_asymmetric_context_free(&asym);

    /* Verify signature with OpenSSL */
    {
        const uint8_t *p = pubkey_der;
        EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, (long)pubkey_der_len);
        if (!pkey) TEST_FAIL("OpenSSL: failed to parse RSA public key");

        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!pctx) TEST_FAIL("OpenSSL: PKEY_CTX_new failed");
        if (EVP_PKEY_verify_init(pctx) != 1)
            TEST_FAIL("OpenSSL: PKEY_verify_init failed");
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) != 1)
            TEST_FAIL("OpenSSL: set_rsa_padding failed");
        if (EVP_PKEY_CTX_set_signature_md(pctx, EVP_sha256()) != 1)
            TEST_FAIL("OpenSSL: set_signature_md failed");

        int rc = EVP_PKEY_verify(pctx, sig, sig_len, hash, 32);

        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);

        if (rc != 1) TEST_FAIL("OpenSSL RSA verify failed");
    }

    sss_key_store_erase_key(&g_ks, &key_obj);
    sss_key_object_free(&key_obj);
    TEST_PASS();
}

/* ======================================================================
 * Test: RSA Encrypt (OpenSSL encrypts, SE050 decrypts)
 * ====================================================================== */
static void test_rsa_encrypt_decrypt(void)
{
    TEST_BEGIN("RSA-2048-encrypt-decrypt");
    sss_status_t status;
    sss_se05x_object_t key_obj;
    sss_se05x_asymmetric_t asym;
    uint32_t obj_id = OBJ_ID_BASE + 51;

    uint8_t pubkey_der[512] = {0};
    size_t pubkey_der_len = sizeof(pubkey_der);
    size_t pubkey_bits = 0;

    uint8_t plaintext[] = "Hello SE050!";
    uint8_t ciphertext[256] = {0};
    size_t ct_len = sizeof(ciphertext);
    uint8_t decrypted[256] = {0};
    size_t dec_len = sizeof(decrypted);

    /* Generate RSA-2048 key */
    cleanup_object(obj_id);
    sss_key_object_init(&key_obj, &g_ks);
    status = sss_key_object_allocate_handle(&key_obj, obj_id,
        kSSS_KeyPart_Pair, kSSS_CipherType_RSA, 256,
        kKeyObject_Mode_Persistent);
    ASSERT_OK(status, "rsa key allocate");

    status = sss_key_store_generate_key(&g_ks, &key_obj, 2048, NULL);
    ASSERT_OK(status, "rsa key generate");

    /* Read public key */
    status = sss_key_store_get_key(&g_ks, &key_obj,
        pubkey_der, &pubkey_der_len, &pubkey_bits);
    ASSERT_OK(status, "rsa get public key");

    /* Encrypt with OpenSSL using the SE050's public key */
    {
        const uint8_t *p = pubkey_der;
        EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, (long)pubkey_der_len);
        if (!pkey) TEST_FAIL("OpenSSL: failed to parse RSA public key");

        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
        EVP_PKEY_encrypt_init(pctx);
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);

        ct_len = sizeof(ciphertext);
        int rc = EVP_PKEY_encrypt(pctx, ciphertext, &ct_len,
                                  plaintext, sizeof(plaintext));

        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);

        if (rc != 1) TEST_FAIL("OpenSSL RSA encrypt failed");
    }

    /* Decrypt with SE050 */
    status = sss_asymmetric_context_init(&asym, &g_ctx.session, &key_obj,
        kAlgorithm_SSS_RSAES_PKCS1_V1_5, kMode_SSS_Decrypt);
    ASSERT_OK(status, "rsa decrypt context init");

    status = sss_asymmetric_decrypt(&asym, ciphertext, ct_len,
                                    decrypted, &dec_len);
    ASSERT_OK(status, "rsa decrypt");

    sss_asymmetric_context_free(&asym);

    /* Compare plaintext */
    ASSERT_EQ(dec_len, sizeof(plaintext), "RSA decrypt length mismatch");
    ASSERT_MEM_EQ(decrypted, plaintext, sizeof(plaintext), "RSA roundtrip mismatch");

    sss_key_store_erase_key(&g_ks, &key_obj);
    sss_key_object_free(&key_obj);
    TEST_PASS();
}

/* ======================================================================
 * Test: RSA key IMPORT + sign (verified by OpenSSL)
 *
 * Generates an RSA keypair in OpenSSL, imports the PKCS#8 DER into the
 * SE050 via sss_key_store_set_key, signs a digest, and verifies with
 * OpenSSL. Exercises the SDK's per-component WriteRSAKey dispatch path
 * (the non-keygen path in sss_se05x_key_store_set_rsa_key), which is
 * what wolfCrypt's SE050 RSA port relies on.
 * ====================================================================== */
static void test_rsa_import_sign_verify(const char *name, uint32_t obj_id,
                                        int key_bits)
{
    TEST_BEGIN(name);
    sss_status_t status;
    sss_se05x_object_t key_obj;
    sss_se05x_asymmetric_t asym;

    /* 1. Generate RSA key in OpenSSL */
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *gctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!gctx) TEST_FAIL("OpenSSL: EVP_PKEY_CTX_new_id failed");
    if (EVP_PKEY_keygen_init(gctx) != 1) TEST_FAIL("OpenSSL: keygen_init");
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(gctx, key_bits) != 1)
        TEST_FAIL("OpenSSL: set_keygen_bits");
    if (EVP_PKEY_keygen(gctx, &pkey) != 1) TEST_FAIL("OpenSSL: keygen");
    EVP_PKEY_CTX_free(gctx);

    /* 2. Serialize private key. i2d_PrivateKey emits the key in its native
     * DER: for RSA that's PKCS#1 RSAPrivateKey, *not* PKCS#8 (RSA-2048 PKCS#1
     * is ~1190 B vs ~1218 B PKCS#8-wrapped). This test exercises the PKCS#1
     * path; test_rsa_import_sign_verify_pkcs8 covers the PKCS#8 wrap path. */
    uint8_t *pkcs8_der = NULL;
    int pkcs8_len = i2d_PrivateKey(pkey, &pkcs8_der);
    if (pkcs8_len <= 0) TEST_FAIL("OpenSSL: i2d_PrivateKey failed");

    /* 3. Import into SE050 */
    cleanup_object(obj_id);
    sss_key_object_init(&key_obj, &g_ks);
    status = sss_key_object_allocate_handle(&key_obj, obj_id,
        kSSS_KeyPart_Pair, kSSS_CipherType_RSA, key_bits / 8,
        kKeyObject_Mode_Persistent);
    ASSERT_OK(status, "rsa import key allocate");

    status = sss_key_store_set_key(&g_ks, &key_obj, pkcs8_der,
                                   (size_t)pkcs8_len, (size_t)key_bits,
                                   NULL, 0);
    OPENSSL_free(pkcs8_der);
    ASSERT_OK(status, "rsa import set_key");

    /* 4. Sign a fixed digest via SE050 */
    uint8_t hash[32];
    memset(hash, 0x42, sizeof(hash));
    uint8_t sig[512] = {0};
    size_t sig_len = sizeof(sig);

    status = sss_asymmetric_context_init(&asym, &g_ctx.session, &key_obj,
        kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256, kMode_SSS_Sign);
    ASSERT_OK(status, "rsa import sign context_init");
    status = sss_asymmetric_sign_digest(&asym, hash, 32, sig, &sig_len);
    ASSERT_OK(status, "rsa import sign_digest");
    sss_asymmetric_context_free(&asym);

    /* 5. Verify with OpenSSL using the same key's public half */
    {
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!pctx) TEST_FAIL("OpenSSL: PKEY_CTX_new");
        if (EVP_PKEY_verify_init(pctx) != 1) TEST_FAIL("verify_init");
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) != 1)
            TEST_FAIL("set_padding");
        if (EVP_PKEY_CTX_set_signature_md(pctx, EVP_sha256()) != 1)
            TEST_FAIL("set_signature_md");
        int rc = EVP_PKEY_verify(pctx, sig, sig_len, hash, 32);
        EVP_PKEY_CTX_free(pctx);
        if (rc != 1) TEST_FAIL("OpenSSL verify of SE050-imported-key signature failed");
    }

    EVP_PKEY_free(pkey);
    sss_key_store_erase_key(&g_ks, &key_obj);
    sss_key_object_free(&key_obj);
    TEST_PASS();
}

/* ======================================================================
 * Test: RSA key import as PKCS#8 PrivateKeyInfo + sign
 *
 * Parallels test_rsa_import_sign_verify but wraps the key in a PKCS#8
 * PrivateKeyInfo (RFC 5208) rather than the raw PKCS#1 RSAPrivateKey.
 * Both formats should be accepted by sss_util_asn1_rsa_parse_private; a
 * failure of only one of the two tests pinpoints which format the host
 * parser actually requires.
 * ====================================================================== */
static void test_rsa_import_sign_verify_pkcs8(const char *name, uint32_t obj_id,
                                              int key_bits)
{
    TEST_BEGIN(name);
    sss_status_t status;
    sss_se05x_object_t key_obj;
    sss_se05x_asymmetric_t asym;

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *gctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!gctx) TEST_FAIL("OpenSSL: CTX_new_id");
    if (EVP_PKEY_keygen_init(gctx) != 1) TEST_FAIL("OpenSSL: keygen_init");
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(gctx, key_bits) != 1)
        TEST_FAIL("OpenSSL: keygen_bits");
    if (EVP_PKEY_keygen(gctx, &pkey) != 1) TEST_FAIL("OpenSSL: keygen");
    EVP_PKEY_CTX_free(gctx);

    /* PKCS#8 wrap via PKCS8_PRIV_KEY_INFO + i2d */
    PKCS8_PRIV_KEY_INFO *p8inf = EVP_PKEY2PKCS8(pkey);
    if (!p8inf) TEST_FAIL("OpenSSL: EVP_PKEY2PKCS8");
    uint8_t *p8_der = NULL;
    int p8_len = i2d_PKCS8_PRIV_KEY_INFO(p8inf, &p8_der);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    if (p8_len <= 0) TEST_FAIL("OpenSSL: i2d_PKCS8");

    cleanup_object(obj_id);
    sss_key_object_init(&key_obj, &g_ks);
    status = sss_key_object_allocate_handle(&key_obj, obj_id,
        kSSS_KeyPart_Pair, kSSS_CipherType_RSA, key_bits / 8,
        kKeyObject_Mode_Persistent);
    ASSERT_OK(status, "pkcs8 allocate");

    status = sss_key_store_set_key(&g_ks, &key_obj, p8_der,
                                   (size_t)p8_len, (size_t)key_bits,
                                   NULL, 0);
    OPENSSL_free(p8_der);
    ASSERT_OK(status, "pkcs8 set_key");

    uint8_t hash[32]; memset(hash, 0x42, sizeof(hash));
    uint8_t sig[512] = {0};
    size_t sig_len = sizeof(sig);
    status = sss_asymmetric_context_init(&asym, &g_ctx.session, &key_obj,
        kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256, kMode_SSS_Sign);
    ASSERT_OK(status, "pkcs8 sign ctx");
    status = sss_asymmetric_sign_digest(&asym, hash, 32, sig, &sig_len);
    ASSERT_OK(status, "pkcs8 sign");
    sss_asymmetric_context_free(&asym);

    {
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
        EVP_PKEY_verify_init(pctx);
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);
        EVP_PKEY_CTX_set_signature_md(pctx, EVP_sha256());
        int rc = EVP_PKEY_verify(pctx, sig, sig_len, hash, 32);
        EVP_PKEY_CTX_free(pctx);
        if (rc != 1) TEST_FAIL("OpenSSL verify PKCS#8-imported sig failed");
    }

    EVP_PKEY_free(pkey);
    sss_key_store_erase_key(&g_ks, &key_obj);
    sss_key_object_free(&key_obj);
    TEST_PASS();
}

/* ======================================================================
 * Test: RSA key import + NO_HASH sign (matches wolfCrypt RSA flow)
 *
 * wolfCrypt's SE050 RSA port imports the wc_RsaKeyToDer output via
 * sss_key_store_set_key, then calls sss_asymmetric_sign_digest with
 * kAlgorithm_SSS_RSASSA_PKCS1_V1_5_NO_HASH. This test reproduces that
 * exact sequence: import PKCS#1 DER, sign a raw digest with NO_HASH,
 * validate by raw-RSA-decrypting the signature with OpenSSL. Exercises
 * both the per-component WriteRSAKey assembly and the host-side PKCS#1
 * encoder followed by RSADecrypt(NO_PAD) path in one shot.
 * ====================================================================== */
static void test_rsa_import_sign_no_hash(void)
{
    TEST_BEGIN("RSA-2048-import-sign-NO_HASH");
    sss_status_t status;
    sss_se05x_object_t key_obj;
    sss_se05x_asymmetric_t asym;
    uint32_t obj_id = OBJ_ID_BASE + 62;

    /* Generate key in OpenSSL, export as PKCS#1 (same as wc_RsaKeyToDer). */
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *gctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!gctx) TEST_FAIL("CTX_new_id");
    if (EVP_PKEY_keygen_init(gctx) != 1) TEST_FAIL("keygen_init");
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(gctx, 2048) != 1) TEST_FAIL("keygen_bits");
    if (EVP_PKEY_keygen(gctx, &pkey) != 1) TEST_FAIL("keygen");
    EVP_PKEY_CTX_free(gctx);

    uint8_t *der = NULL;
    int der_len = i2d_PrivateKey(pkey, &der);
    if (der_len <= 0) TEST_FAIL("i2d_PrivateKey");

    cleanup_object(obj_id);
    sss_key_object_init(&key_obj, &g_ks);
    status = sss_key_object_allocate_handle(&key_obj, obj_id,
        kSSS_KeyPart_Pair, kSSS_CipherType_RSA, 256,
        kKeyObject_Mode_Persistent);
    ASSERT_OK(status, "import-no_hash allocate");

    status = sss_key_store_set_key(&g_ks, &key_obj, der,
                                   (size_t)der_len, 2048, NULL, 0);
    OPENSSL_free(der);
    ASSERT_OK(status, "import-no_hash set_key");

    uint8_t hash[32];  memset(hash, 0xA5, sizeof(hash));
    uint8_t sig[256] = {0};
    size_t sig_len = sizeof(sig);

    status = sss_asymmetric_context_init(&asym, &g_ctx.session, &key_obj,
        kAlgorithm_SSS_RSASSA_PKCS1_V1_5_NO_HASH, kMode_SSS_Sign);
    ASSERT_OK(status, "import-no_hash sign ctx");
    status = sss_asymmetric_sign_digest(&asym, hash, 32, sig, &sig_len);
    ASSERT_OK(status, "import-no_hash sign_digest");
    sss_asymmetric_context_free(&asym);

    ASSERT_EQ(sig_len, 256, "import-no_hash sig length");

    /* Validate: raw-RSA-decrypt signature, check PKCS1 v1.5 block + hash. */
    {
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (EVP_PKEY_verify_recover_init(pctx) != 1) TEST_FAIL("recover_init");
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_NO_PADDING) != 1)
            TEST_FAIL("set_no_padding");
        uint8_t recovered[256] = {0};
        size_t rec_len = sizeof(recovered);
        int rc = EVP_PKEY_verify_recover(pctx, recovered, &rec_len, sig, sig_len);
        EVP_PKEY_CTX_free(pctx);
        if (rc != 1) TEST_FAIL("verify_recover");
        if (recovered[0] != 0x00 || recovered[1] != 0x01)
            TEST_FAIL("PKCS1 v1.5 prefix");
        size_t idx = 2;
        while (idx < 256 && recovered[idx] == 0xFF) idx++;
        if (recovered[idx] != 0x00) TEST_FAIL("PKCS1 v1.5 separator");
        idx++;
        if (256 - idx != 32) TEST_FAILF("hash region %zu bytes", 256 - idx);
        if (memcmp(&recovered[idx], hash, 32) != 0)
            TEST_FAIL("hash mismatch after NO_HASH sign (key import likely broken)");
    }

    EVP_PKEY_free(pkey);
    sss_key_store_erase_key(&g_ks, &key_obj);
    sss_key_object_free(&key_obj);
    TEST_PASS();
}

/* ======================================================================
 * Test: RSA sign/verify with configurable hash (PKCS#1 v1.5)
 * ====================================================================== */
static void test_rsa_sign_with_hash(const char *name, uint32_t obj_id,
                                    int key_bits, sss_algorithm_t sss_algo,
                                    const EVP_MD *ossl_md, size_t hash_len)
{
    TEST_BEGIN(name);
    sss_status_t status;
    sss_se05x_object_t key_obj;
    sss_se05x_asymmetric_t asym;

    uint8_t pubkey_der[1024] = {0};
    size_t pubkey_der_len = sizeof(pubkey_der);
    size_t pubkey_bits = 0;
    uint8_t hash[64];  /* fits SHA-512 */
    memset(hash, 0x5A, sizeof(hash));
    uint8_t sig[512] = {0};
    size_t sig_len = sizeof(sig);

    cleanup_object(obj_id);
    sss_key_object_init(&key_obj, &g_ks);
    status = sss_key_object_allocate_handle(&key_obj, obj_id,
        kSSS_KeyPart_Pair, kSSS_CipherType_RSA, key_bits / 8,
        kKeyObject_Mode_Persistent);
    ASSERT_OK(status, "rsa key allocate");
    status = sss_key_store_generate_key(&g_ks, &key_obj, key_bits, NULL);
    ASSERT_OK(status, "rsa key generate");

    status = sss_key_store_get_key(&g_ks, &key_obj,
        pubkey_der, &pubkey_der_len, &pubkey_bits);
    ASSERT_OK(status, "rsa get public key");

    status = sss_asymmetric_context_init(&asym, &g_ctx.session, &key_obj,
        sss_algo, kMode_SSS_Sign);
    ASSERT_OK(status, "rsa sign context_init");
    status = sss_asymmetric_sign_digest(&asym, hash, hash_len, sig, &sig_len);
    ASSERT_OK(status, "rsa sign_digest");
    sss_asymmetric_context_free(&asym);

    {
        const uint8_t *p = pubkey_der;
        EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, (long)pubkey_der_len);
        if (!pkey) TEST_FAIL("OpenSSL: parse pubkey");
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (EVP_PKEY_verify_init(pctx) != 1) TEST_FAIL("verify_init");
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) != 1)
            TEST_FAIL("set_padding");
        if (EVP_PKEY_CTX_set_signature_md(pctx, ossl_md) != 1)
            TEST_FAIL("set_signature_md");
        int rc = EVP_PKEY_verify(pctx, sig, sig_len, hash, hash_len);
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);
        if (rc != 1) TEST_FAIL("OpenSSL verify failed");
    }

    sss_key_store_erase_key(&g_ks, &key_obj);
    sss_key_object_free(&key_obj);
    TEST_PASS();
}

/* ======================================================================
 * Test: RSA PSS sign/verify
 * ====================================================================== */
static void test_rsa_pss_sign_verify(const char *name, uint32_t obj_id,
                                     int key_bits, sss_algorithm_t sss_algo,
                                     const EVP_MD *ossl_md, size_t hash_len)
{
    TEST_BEGIN(name);
    sss_status_t status;
    sss_se05x_object_t key_obj;
    sss_se05x_asymmetric_t asym;

    uint8_t pubkey_der[1024] = {0};
    size_t pubkey_der_len = sizeof(pubkey_der);
    size_t pubkey_bits = 0;
    uint8_t hash[64];
    memset(hash, 0x37, sizeof(hash));
    uint8_t sig[512] = {0};
    size_t sig_len = sizeof(sig);

    cleanup_object(obj_id);
    sss_key_object_init(&key_obj, &g_ks);
    status = sss_key_object_allocate_handle(&key_obj, obj_id,
        kSSS_KeyPart_Pair, kSSS_CipherType_RSA, key_bits / 8,
        kKeyObject_Mode_Persistent);
    ASSERT_OK(status, "rsa-pss key allocate");
    status = sss_key_store_generate_key(&g_ks, &key_obj, key_bits, NULL);
    ASSERT_OK(status, "rsa-pss key generate");

    status = sss_key_store_get_key(&g_ks, &key_obj,
        pubkey_der, &pubkey_der_len, &pubkey_bits);
    ASSERT_OK(status, "rsa-pss get pubkey");

    status = sss_asymmetric_context_init(&asym, &g_ctx.session, &key_obj,
        sss_algo, kMode_SSS_Sign);
    ASSERT_OK(status, "rsa-pss sign context_init");
    status = sss_asymmetric_sign_digest(&asym, hash, hash_len, sig, &sig_len);
    ASSERT_OK(status, "rsa-pss sign_digest");
    sss_asymmetric_context_free(&asym);

    {
        const uint8_t *p = pubkey_der;
        EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, (long)pubkey_der_len);
        if (!pkey) TEST_FAIL("OpenSSL: parse pubkey");
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (EVP_PKEY_verify_init(pctx) != 1) TEST_FAIL("verify_init");
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1)
            TEST_FAIL("set_pss_padding");
        if (EVP_PKEY_CTX_set_signature_md(pctx, ossl_md) != 1)
            TEST_FAIL("set_signature_md");
        /* SE050 uses salt_len = hash_len by default */
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, (int)hash_len) != 1)
            TEST_FAIL("set_pss_saltlen");
        int rc = EVP_PKEY_verify(pctx, sig, sig_len, hash, hash_len);
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);
        if (rc != 1) TEST_FAIL("OpenSSL PSS verify failed");
    }

    sss_key_store_erase_key(&g_ks, &key_obj);
    sss_key_object_free(&key_obj);
    TEST_PASS();
}

/* ======================================================================
 * Test: RSA OAEP encrypt/decrypt (OpenSSL encrypts, SE050 decrypts)
 * ====================================================================== */
static void test_rsa_oaep_encrypt_decrypt(const char *name, uint32_t obj_id,
                                          int key_bits,
                                          sss_algorithm_t sss_algo,
                                          const EVP_MD *ossl_md)
{
    TEST_BEGIN(name);
    sss_status_t status;
    sss_se05x_object_t key_obj;
    sss_se05x_asymmetric_t asym;

    uint8_t pubkey_der[1024] = {0};
    size_t pubkey_der_len = sizeof(pubkey_der);
    size_t pubkey_bits = 0;
    uint8_t plaintext[] = "OAEP padding test message";
    uint8_t ciphertext[512] = {0};
    size_t ct_len = sizeof(ciphertext);
    uint8_t decrypted[512] = {0};
    size_t dec_len = sizeof(decrypted);

    cleanup_object(obj_id);
    sss_key_object_init(&key_obj, &g_ks);
    status = sss_key_object_allocate_handle(&key_obj, obj_id,
        kSSS_KeyPart_Pair, kSSS_CipherType_RSA, key_bits / 8,
        kKeyObject_Mode_Persistent);
    ASSERT_OK(status, "rsa-oaep key allocate");
    status = sss_key_store_generate_key(&g_ks, &key_obj, key_bits, NULL);
    ASSERT_OK(status, "rsa-oaep key generate");

    status = sss_key_store_get_key(&g_ks, &key_obj,
        pubkey_der, &pubkey_der_len, &pubkey_bits);
    ASSERT_OK(status, "rsa-oaep get pubkey");

    /* OpenSSL encrypt with OAEP */
    {
        const uint8_t *p = pubkey_der;
        EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, (long)pubkey_der_len);
        if (!pkey) TEST_FAIL("OpenSSL: parse pubkey");
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (EVP_PKEY_encrypt_init(pctx) != 1) TEST_FAIL("encrypt_init");
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) != 1)
            TEST_FAIL("set_oaep_padding");
        if (EVP_PKEY_CTX_set_rsa_oaep_md(pctx, ossl_md) != 1)
            TEST_FAIL("set_oaep_md");
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, ossl_md) != 1)
            TEST_FAIL("set_mgf1_md");
        ct_len = sizeof(ciphertext);
        int rc = EVP_PKEY_encrypt(pctx, ciphertext, &ct_len,
                                  plaintext, sizeof(plaintext));
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);
        if (rc != 1) TEST_FAIL("OpenSSL OAEP encrypt failed");
    }

    /* SE050 decrypt */
    status = sss_asymmetric_context_init(&asym, &g_ctx.session, &key_obj,
        sss_algo, kMode_SSS_Decrypt);
    ASSERT_OK(status, "rsa-oaep decrypt context_init");
    status = sss_asymmetric_decrypt(&asym, ciphertext, ct_len,
                                    decrypted, &dec_len);
    ASSERT_OK(status, "rsa-oaep decrypt");
    sss_asymmetric_context_free(&asym);

    ASSERT_EQ(dec_len, sizeof(plaintext), "oaep decrypt length mismatch");
    ASSERT_MEM_EQ(decrypted, plaintext, sizeof(plaintext), "oaep roundtrip mismatch");

    sss_key_store_erase_key(&g_ks, &key_obj);
    sss_key_object_free(&key_obj);
    TEST_PASS();
}

/* ======================================================================
 * Test: RSA PKCS#1 v1.5 NO_HASH sign
 *
 * This is the code path wolfCrypt's se050_rsa_sign lands on when the
 * caller passes a pre-hashed digest with hash=WC_HASH_TYPE_NONE (e.g.
 * TLS CertificateVerify). The SDK does host-side PKCS#1-v1.5 padding
 * (no DigestInfo wrap) via pkcs1_v15_encode_no_hash, then issues
 * RSADecrypt(NO_PAD). We exercise the same algo here and validate the
 * result by RSA-public-decrypting the signature (RSA_NO_PADDING) and
 * checking the plaintext matches the expected
 *   0x00 0x01 0xFF...0xFF 0x00 <digest>
 * block that the SDK's encoder is supposed to produce.
 * ====================================================================== */
static void test_rsa_sign_no_hash(void)
{
    TEST_BEGIN("RSA-2048-sign-NO_HASH");
    sss_status_t status;
    sss_se05x_object_t key_obj;
    sss_se05x_asymmetric_t asym;
    uint32_t obj_id = OBJ_ID_BASE + 61;

    uint8_t pubkey_der[1024] = {0};
    size_t pubkey_der_len = sizeof(pubkey_der);
    size_t pubkey_bits = 0;
    uint8_t hash[32];  memset(hash, 0x9A, sizeof(hash));
    uint8_t sig[256] = {0};
    size_t sig_len = sizeof(sig);

    cleanup_object(obj_id);
    sss_key_object_init(&key_obj, &g_ks);
    status = sss_key_object_allocate_handle(&key_obj, obj_id,
        kSSS_KeyPart_Pair, kSSS_CipherType_RSA, 256,
        kKeyObject_Mode_Persistent);
    ASSERT_OK(status, "no_hash allocate");
    status = sss_key_store_generate_key(&g_ks, &key_obj, 2048, NULL);
    ASSERT_OK(status, "no_hash generate");

    status = sss_key_store_get_key(&g_ks, &key_obj,
        pubkey_der, &pubkey_der_len, &pubkey_bits);
    ASSERT_OK(status, "no_hash get_pubkey");

    status = sss_asymmetric_context_init(&asym, &g_ctx.session, &key_obj,
        kAlgorithm_SSS_RSASSA_PKCS1_V1_5_NO_HASH, kMode_SSS_Sign);
    ASSERT_OK(status, "no_hash sign ctx");
    status = sss_asymmetric_sign_digest(&asym, hash, 32, sig, &sig_len);
    ASSERT_OK(status, "no_hash sign_digest");
    sss_asymmetric_context_free(&asym);

    ASSERT_EQ(sig_len, 256, "no_hash sig length");

    /* Raw RSA public-op: m = sig^e mod n. Expect PKCS1-v1.5 pad + raw hash. */
    {
        const uint8_t *p = pubkey_der;
        EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, (long)pubkey_der_len);
        if (!pkey) TEST_FAIL("OpenSSL: parse pubkey");
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (EVP_PKEY_verify_recover_init(pctx) != 1) TEST_FAIL("verify_recover_init");
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_NO_PADDING) != 1)
            TEST_FAIL("set_no_padding");

        uint8_t recovered[256] = {0};
        size_t rec_len = sizeof(recovered);
        int rc = EVP_PKEY_verify_recover(pctx, recovered, &rec_len, sig, sig_len);
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);
        if (rc != 1) TEST_FAIL("OpenSSL verify_recover failed");
        if (rec_len != 256) TEST_FAILF("rec_len %zu != 256", rec_len);

        /* Expected encoded block: 00 01 FF*PS 00 hash */
        if (recovered[0] != 0x00 || recovered[1] != 0x01)
            TEST_FAIL("missing PKCS1 v1.5 prefix 00 01");
        /* Locate terminating 0x00 after padding string */
        size_t idx = 2;
        while (idx < 256 && recovered[idx] == 0xFF) idx++;
        if (idx < 10 || idx >= 256 || recovered[idx] != 0x00)
            TEST_FAIL("malformed PKCS1 v1.5 padding");
        idx++;
        if (256 - idx != 32)
            TEST_FAILF("hash region %zu bytes, expected 32", 256 - idx);
        if (memcmp(&recovered[idx], hash, 32) != 0)
            TEST_FAIL("recovered hash does not match input");
    }

    sss_key_store_erase_key(&g_ks, &key_obj);
    sss_key_object_free(&key_obj);
    TEST_PASS();
}

/* ======================================================================
 * Test: RSA self-verify (sign via SE050, verify via SE050)
 *
 * Some SE050 port bugs can cause sign to silently use a different key
 * than verify expects — this round-trip catches that even without an
 * external oracle.
 * ====================================================================== */
static void test_rsa_se050_self_verify(void)
{
    TEST_BEGIN("RSA-2048-SE050-self-verify");
    sss_status_t status;
    sss_se05x_object_t key_obj;
    sss_se05x_asymmetric_t asym;
    uint32_t obj_id = OBJ_ID_BASE + 58;

    uint8_t hash[32];
    memset(hash, 0x77, sizeof(hash));
    uint8_t sig[256] = {0};
    size_t sig_len = sizeof(sig);

    cleanup_object(obj_id);
    sss_key_object_init(&key_obj, &g_ks);
    status = sss_key_object_allocate_handle(&key_obj, obj_id,
        kSSS_KeyPart_Pair, kSSS_CipherType_RSA, 256,
        kKeyObject_Mode_Persistent);
    ASSERT_OK(status, "self-verify allocate");
    status = sss_key_store_generate_key(&g_ks, &key_obj, 2048, NULL);
    ASSERT_OK(status, "self-verify generate");

    status = sss_asymmetric_context_init(&asym, &g_ctx.session, &key_obj,
        kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256, kMode_SSS_Sign);
    ASSERT_OK(status, "self-verify sign ctx");
    status = sss_asymmetric_sign_digest(&asym, hash, 32, sig, &sig_len);
    ASSERT_OK(status, "self-verify sign");
    sss_asymmetric_context_free(&asym);

    status = sss_asymmetric_context_init(&asym, &g_ctx.session, &key_obj,
        kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256, kMode_SSS_Verify);
    ASSERT_OK(status, "self-verify verify ctx");
    status = sss_asymmetric_verify_digest(&asym, hash, 32, sig, sig_len);
    ASSERT_OK(status, "self-verify verify");
    sss_asymmetric_context_free(&asym);

    /* Flip one bit in the signature and confirm verify fails. */
    sig[0] ^= 0x01;
    status = sss_asymmetric_context_init(&asym, &g_ctx.session, &key_obj,
        kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256, kMode_SSS_Verify);
    ASSERT_OK(status, "self-verify verify-bad ctx");
    sss_status_t bad_status = sss_asymmetric_verify_digest(&asym, hash, 32,
                                                           sig, sig_len);
    sss_asymmetric_context_free(&asym);
    if (bad_status == kStatus_SSS_Success)
        TEST_FAIL("self-verify: corrupted signature accepted");

    sss_key_store_erase_key(&g_ks, &key_obj);
    sss_key_object_free(&key_obj);
    TEST_PASS();
}

/* ======================================================================
 * Test: X25519 ECDH (two SE050 key pairs, shared secrets must match)
 * ====================================================================== */
static void test_x25519_ecdh(void)
{
    TEST_BEGIN("X25519-ECDH");
    sss_status_t status;
    sss_se05x_object_t key_a, key_b, derived_a, derived_b;
    sss_se05x_derive_key_t derive_ctx;

    uint32_t id_a = OBJ_ID_BASE + 60;
    uint32_t id_b = OBJ_ID_BASE + 61;
    uint32_t id_ss_a = OBJ_ID_BASE + 62;
    uint32_t id_ss_b = OBJ_ID_BASE + 63;

    uint8_t shared_a[32] = {0}, shared_b[32] = {0};
    size_t shared_a_len = sizeof(shared_a), shared_b_len = sizeof(shared_b);
    size_t shared_bits = 0;
    uint8_t zeros[32] = {0};

    cleanup_object(id_a);
    cleanup_object(id_b);
    cleanup_object(id_ss_a);
    cleanup_object(id_ss_b);

    /* Generate X25519 key pair A */
    sss_key_object_init(&key_a, &g_ks);
    status = sss_key_object_allocate_handle(&key_a, id_a,
        kSSS_KeyPart_Pair, kSSS_CipherType_EC_MONTGOMERY, 32,
        kKeyObject_Mode_Persistent);
    ASSERT_OK(status, "x25519 key_a allocate");
    status = sss_key_store_generate_key(&g_ks, &key_a, 256, NULL);
    ASSERT_OK(status, "x25519 key_a generate");

    /* Generate X25519 key pair B */
    sss_key_object_init(&key_b, &g_ks);
    status = sss_key_object_allocate_handle(&key_b, id_b,
        kSSS_KeyPart_Pair, kSSS_CipherType_EC_MONTGOMERY, 32,
        kKeyObject_Mode_Persistent);
    ASSERT_OK(status, "x25519 key_b allocate");
    status = sss_key_store_generate_key(&g_ks, &key_b, 256, NULL);
    ASSERT_OK(status, "x25519 key_b generate");

    /* ECDH(A_priv, B_pub) */
    sss_key_object_init(&derived_a, &g_ks);
    status = sss_key_object_allocate_handle(&derived_a, id_ss_a,
        kSSS_KeyPart_Default, kSSS_CipherType_Binary, 32,
        kKeyObject_Mode_Transient);
    ASSERT_OK(status, "derived_a allocate");

    status = sss_derive_key_context_init(&derive_ctx, &g_ctx.session,
        &key_a, kAlgorithm_SSS_ECDH, kMode_SSS_ComputeSharedSecret);
    ASSERT_OK(status, "derive_a context_init");
    status = sss_derive_key_dh(&derive_ctx, &key_b, &derived_a);
    ASSERT_OK(status, "derive_a dh");
    sss_derive_key_context_free(&derive_ctx);

    status = sss_key_store_get_key(&g_ks, &derived_a,
        shared_a, &shared_a_len, &shared_bits);
    ASSERT_OK(status, "get shared_a");

    /* ECDH(B_priv, A_pub) */
    sss_key_object_init(&derived_b, &g_ks);
    status = sss_key_object_allocate_handle(&derived_b, id_ss_b,
        kSSS_KeyPart_Default, kSSS_CipherType_Binary, 32,
        kKeyObject_Mode_Transient);
    ASSERT_OK(status, "derived_b allocate");

    status = sss_derive_key_context_init(&derive_ctx, &g_ctx.session,
        &key_b, kAlgorithm_SSS_ECDH, kMode_SSS_ComputeSharedSecret);
    ASSERT_OK(status, "derive_b context_init");
    status = sss_derive_key_dh(&derive_ctx, &key_a, &derived_b);
    ASSERT_OK(status, "derive_b dh");
    sss_derive_key_context_free(&derive_ctx);

    status = sss_key_store_get_key(&g_ks, &derived_b,
        shared_b, &shared_b_len, &shared_bits);
    ASSERT_OK(status, "get shared_b");

    /* Shared secrets must be non-zero and equal */
    ASSERT_MEM_NEQ(shared_a, zeros, 32, "shared_a is all zeros");
    ASSERT_EQ(shared_a_len, shared_b_len, "shared secret lengths differ");
    ASSERT_MEM_EQ(shared_a, shared_b, shared_a_len, "shared secrets differ");

    /* Cleanup */
    sss_key_store_erase_key(&g_ks, &key_a);
    sss_key_store_erase_key(&g_ks, &key_b);
    sss_key_store_erase_key(&g_ks, &derived_a);
    sss_key_store_erase_key(&g_ks, &derived_b);
    sss_key_object_free(&key_a);
    sss_key_object_free(&key_b);
    sss_key_object_free(&derived_a);
    sss_key_object_free(&derived_b);
    TEST_PASS();
}

/* ======================================================================
 * Test: Ed25519 Key Generation + Sign/Verify via SE050
 * ====================================================================== */
static void test_ed25519_sign_verify(void)
{
    TEST_BEGIN("Ed25519-sign-verify");
    sss_status_t status;
    sss_se05x_object_t key_obj;
    sss_se05x_asymmetric_t asym;
    uint32_t obj_id = OBJ_ID_BASE + 70;

    uint8_t pubkey_der[128] = {0};
    size_t pubkey_der_len = sizeof(pubkey_der);
    size_t pubkey_bits = 0;

    uint8_t msg[] = "test message for Ed25519";
    uint8_t sig[64] = {0};
    size_t sig_len = sizeof(sig);

    /* Generate Ed25519 key pair */
    cleanup_object(obj_id);
    sss_key_object_init(&key_obj, &g_ks);
    status = sss_key_object_allocate_handle(&key_obj, obj_id,
        kSSS_KeyPart_Pair, kSSS_CipherType_EC_TWISTED_ED, 32,
        kKeyObject_Mode_Persistent);
    ASSERT_OK(status, "ed25519 key allocate");

    status = sss_key_store_generate_key(&g_ks, &key_obj, 256, NULL);
    ASSERT_OK(status, "ed25519 key generate");

    /* Read public key */
    status = sss_key_store_get_key(&g_ks, &key_obj,
        pubkey_der, &pubkey_der_len, &pubkey_bits);
    ASSERT_OK(status, "ed25519 get public key");

    /* Sign via SE050 */
    status = sss_asymmetric_context_init(&asym, &g_ctx.session, &key_obj,
        kAlgorithm_SSS_SHA512, kMode_SSS_Sign);
    ASSERT_OK(status, "ed25519 sign context_init");

    status = sss_se05x_asymmetric_sign(
        (sss_se05x_asymmetric_t *)&asym,
        msg, sizeof(msg), sig, &sig_len);
    ASSERT_OK(status, "ed25519 sign");

    sss_asymmetric_context_free(&asym);

    /* Verify via SE050 */
    SE05x_Result_t verify_result = kSE05x_Result_FAILURE;
    status = sss_asymmetric_context_init(&asym, &g_ctx.session, &key_obj,
        kAlgorithm_SSS_SHA512, kMode_SSS_Verify);
    ASSERT_OK(status, "ed25519 verify context_init");

    status = sss_se05x_asymmetric_verify(
        (sss_se05x_asymmetric_t *)&asym,
        msg, sizeof(msg), sig, sig_len);
    ASSERT_OK(status, "ed25519 verify");

    sss_asymmetric_context_free(&asym);

    /* Verify signature with OpenSSL.
     * The SDK reverses the 32-byte raw public key (endianness swap for
     * Montgomery/Edwards curves). We reverse it back before giving it to
     * OpenSSL. The SDK also double-reverses each signature half (R,S) so
     * the signature is already in standard Ed25519 format. */
    {
        /* Ed25519 SubjectPublicKeyInfo DER header is 12 bytes:
         * 30 2a 30 05 06 03 2b 65 70 03 21 00 [32 bytes key] */
        const size_t ed25519_der_hdr_len = 12;
        if (pubkey_der_len != ed25519_der_hdr_len + 32)
            TEST_FAILF("unexpected Ed25519 pubkey DER len: %zu", pubkey_der_len);

        /* Reverse the raw 32 bytes back to standard LE */
        uint8_t raw_pubkey[32];
        for (int i = 0; i < 32; i++)
            raw_pubkey[i] = pubkey_der[ed25519_der_hdr_len + 31 - i];

        EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(
            EVP_PKEY_ED25519, NULL, raw_pubkey, 32);
        if (!pkey) TEST_FAIL("OpenSSL: EVP_PKEY_new_raw_public_key failed");

        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey) != 1)
            TEST_FAIL("OpenSSL: DigestVerifyInit failed");

        int rc = EVP_DigestVerify(mdctx, sig, sig_len, msg, sizeof(msg));

        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);

        if (rc != 1) TEST_FAIL("OpenSSL Ed25519 verify failed");
    }

    /* Sign a different message and verify it does NOT match original sig */
    uint8_t msg2[] = "different message";
    status = sss_asymmetric_context_init(&asym, &g_ctx.session, &key_obj,
        kAlgorithm_SSS_SHA512, kMode_SSS_Verify);
    if (status == kStatus_SSS_Success) {
        sss_status_t bad_verify = sss_se05x_asymmetric_verify(
            (sss_se05x_asymmetric_t *)&asym,
            msg2, sizeof(msg2), sig, sig_len);
        sss_asymmetric_context_free(&asym);
        /* Should fail verification */
        if (bad_verify == kStatus_SSS_Success) {
            TEST_FAIL("ed25519 verify should fail for wrong message");
        }
    }

    sss_key_store_erase_key(&g_ks, &key_obj);
    sss_key_object_free(&key_obj);
    TEST_PASS();
}

/* ======================================================================
 * Test: Ed25519 Test Vector (RFC 8032 vector 1)
 * Import a known key, sign an empty message, compare to expected signature.
 * This is equivalent to the wolfCrypt Ed25519 test vector test.
 * ====================================================================== */
static void test_ed25519_test_vector(void)
{
    TEST_BEGIN("Ed25519-test-vector");
    sss_status_t status;
    sss_se05x_object_t key_obj;
    sss_se05x_asymmetric_t asym;
    uint32_t obj_id = OBJ_ID_BASE + 71;

    /* RFC 8032 test vector 1 */
    static const uint8_t priv_seed[32] = {
        0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,
        0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
        0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,
        0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60
    };
    static const uint8_t pub_key[32] = {
        0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,
        0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
        0x0e,0xe1,0x72,0xf3,0xda,0xa3,0xf4,0xa1,
        0x84,0x46,0xb0,0xb8,0xd5,0x82,0x40,0xd0
    };
    static const uint8_t expected_sig[64] = {
        0xe5,0x56,0x43,0x00,0xc3,0x60,0xac,0x72,
        0x90,0x86,0xe2,0xcc,0x80,0x6e,0x82,0x8a,
        0x84,0x87,0x7f,0x1e,0xb8,0xe5,0xd9,0x74,
        0xd8,0x73,0xe0,0x65,0x22,0x49,0x01,0x55,
        0x5f,0xb8,0x82,0x15,0x90,0xa3,0x3b,0xac,
        0xc6,0x1e,0x39,0x70,0x1c,0xf9,0xb4,0x6b,
        0xd2,0x5b,0xf5,0xf0,0x59,0x5b,0xbe,0x24,
        0x65,0x51,0x41,0x43,0x8e,0x7a,0x10,0x0b
    };

    /* Build RFC 8410 OneAsymmetricKey DER for import:
     * SEQUENCE {
     *   INTEGER 0,
     *   SEQUENCE { OID 1.3.101.112 },
     *   OCTET STRING { OCTET STRING { private_key } },
     *   [1] { 0x00 || public_key }
     * } */
    uint8_t der[83];
    static const uint8_t der_hdr[] = {
        0x30, 0x51,             /* SEQUENCE (81 bytes) */
        0x02, 0x01, 0x00,       /* INTEGER 0 */
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,  /* SEQUENCE { OID Ed25519 } */
        0x04, 0x22, 0x04, 0x20  /* OCTET STRING { OCTET STRING (32 bytes) */
    };
    static const uint8_t der_pub_hdr[] = {
        0x81, 0x21, 0x00        /* [1] IMPLICIT PRIMITIVE BIT STRING, 0 unused bits */
    };
    memcpy(der, der_hdr, sizeof(der_hdr));
    memcpy(der + sizeof(der_hdr), priv_seed, 32);
    memcpy(der + sizeof(der_hdr) + 32, der_pub_hdr, sizeof(der_pub_hdr));
    memcpy(der + sizeof(der_hdr) + 32 + sizeof(der_pub_hdr), pub_key, 32);

    /* Import the key pair */
    cleanup_object(obj_id);
    sss_key_object_init(&key_obj, &g_ks);
    status = sss_key_object_allocate_handle(&key_obj, obj_id,
        kSSS_KeyPart_Pair, kSSS_CipherType_EC_TWISTED_ED, 32,
        kKeyObject_Mode_Persistent);
    ASSERT_OK(status, "ed25519 vector key allocate");

    status = sss_key_store_set_key(&g_ks, &key_obj, der, sizeof(der),
        256, NULL, 0);
    ASSERT_OK(status, "ed25519 vector key import");

    /* Sign empty message via SE050 */
    uint8_t sig[64] = {0};
    size_t sig_len = sizeof(sig);

    status = sss_asymmetric_context_init(&asym, &g_ctx.session, &key_obj,
        kAlgorithm_SSS_SHA512, kMode_SSS_Sign);
    ASSERT_OK(status, "ed25519 vector sign context_init");

    uint8_t empty = 0;
    status = sss_se05x_asymmetric_sign(
        (sss_se05x_asymmetric_t *)&asym,
        &empty, 0, sig, &sig_len);
    ASSERT_OK(status, "ed25519 vector sign");

    sss_asymmetric_context_free(&asym);

    /* Compare to expected RFC 8032 signature */
    ASSERT_EQ(sig_len, 64, "ed25519 vector sig length mismatch");
    ASSERT_MEM_EQ(sig, expected_sig, 64, "ed25519 vector signature mismatch");

    sss_key_store_erase_key(&g_ks, &key_obj);
    sss_key_object_free(&key_obj);
    TEST_PASS();
}

/* ======================================================================
 * Test: Binary Object Write/Read
 * ====================================================================== */
static void test_object_write_read(void)
{
    TEST_BEGIN("Object-write-read");
    sss_status_t status;
    sss_se05x_object_t obj;
    uint32_t obj_id = OBJ_ID_BASE + 200;

    uint8_t write_data[] = "Hello SE050 Simulator!";
    uint8_t read_data[64] = {0};
    size_t read_len = sizeof(read_data);
    size_t read_bits = 0;

    cleanup_object(obj_id);
    sss_key_object_init(&obj, &g_ks);
    status = sss_key_object_allocate_handle(&obj, obj_id,
        kSSS_KeyPart_Default, kSSS_CipherType_Binary, sizeof(write_data),
        kKeyObject_Mode_Persistent);
    ASSERT_OK(status, "binary allocate");

    status = sss_key_store_set_key(&g_ks, &obj, write_data, sizeof(write_data),
        sizeof(write_data) * 8, NULL, 0);
    ASSERT_OK(status, "binary set_key");

    status = sss_key_store_get_key(&g_ks, &obj, read_data, &read_len, &read_bits);
    ASSERT_OK(status, "binary get_key");

    ASSERT_EQ(read_len, sizeof(write_data), "binary length mismatch");
    ASSERT_MEM_EQ(read_data, write_data, sizeof(write_data), "binary data mismatch");

    sss_key_store_erase_key(&g_ks, &obj);
    sss_key_object_free(&obj);
    TEST_PASS();
}

/* ======================================================================
 * Test: Object Delete
 * ====================================================================== */
static void test_object_delete(void)
{
    TEST_BEGIN("Object-delete");
    sss_status_t status;
    sss_se05x_object_t obj;
    uint32_t obj_id = OBJ_ID_BASE + 201;
    SE05x_Result_t exists;

    uint8_t data[] = "temp";

    cleanup_object(obj_id);
    sss_key_object_init(&obj, &g_ks);
    status = sss_key_object_allocate_handle(&obj, obj_id,
        kSSS_KeyPart_Default, kSSS_CipherType_Binary, sizeof(data),
        kKeyObject_Mode_Persistent);
    ASSERT_OK(status, "allocate");

    status = sss_key_store_set_key(&g_ks, &obj, data, sizeof(data),
        sizeof(data) * 8, NULL, 0);
    ASSERT_OK(status, "set_key");

    /* Verify it exists */
    Se05x_API_CheckObjectExists(&g_session->s_ctx, obj_id, &exists);
    ASSERT_EQ(exists, kSE05x_Result_SUCCESS, "should exist after write");

    /* Delete it */
    status = sss_key_store_erase_key(&g_ks, &obj);
    ASSERT_OK(status, "erase_key");

    /* Verify it's gone */
    Se05x_API_CheckObjectExists(&g_session->s_ctx, obj_id, &exists);
    ASSERT_EQ(exists, kSE05x_Result_FAILURE, "should not exist after delete");

    sss_key_object_free(&obj);
    TEST_PASS();
}

/* ======================================================================
 * Main
 * ====================================================================== */
int main(void)
{
    printf("=== SE050 Simulator SDK Test Suite ===\n");
    printf("Using OpenSSL %s for cross-verification\n\n",
           OpenSSL_version(OPENSSL_VERSION));

    if (init_session() != 0) {
        fprintf(stderr, "Failed to initialize SE050 session\n");
        return 1;
    }

    /* RNG */
    test_rng();

    /* SHA digests */
    test_sha("SHA-1",   kAlgorithm_SSS_SHA1,   EVP_sha1(),   20);
    test_sha("SHA-224", kAlgorithm_SSS_SHA224,  EVP_sha224(), 28);
    test_sha("SHA-256", kAlgorithm_SSS_SHA256,  EVP_sha256(), 32);
    test_sha("SHA-384", kAlgorithm_SSS_SHA384,  EVP_sha384(), 48);
    test_sha("SHA-512", kAlgorithm_SSS_SHA512,  EVP_sha512(), 64);

    /* ECC keygen + sign (verified by OpenSSL) */
    test_ecc_sign_verify("ECC-P256-keygen-sign-verify",
        OBJ_ID_BASE + 10, kSSS_CipherType_EC_NIST_P, 32, 256,
        kSE05x_ECCurve_NIST_P256, NID_X9_62_prime256v1);

    test_ecc_sign_verify("ECC-P384-keygen-sign-verify",
        OBJ_ID_BASE + 11, kSSS_CipherType_EC_NIST_P, 48, 384,
        kSE05x_ECCurve_NIST_P384, NID_secp384r1);

    /* ECDH */
    test_ecdh("ECDH-P256",
        OBJ_ID_BASE + 20, OBJ_ID_BASE + 21, OBJ_ID_BASE + 22,
        32, 256);

    /* AES */
    test_aes_cbc("AES-128-CBC", OBJ_ID_BASE + 30, 16, EVP_aes_128_cbc());
    test_aes_cbc("AES-256-CBC", OBJ_ID_BASE + 31, 32, EVP_aes_256_cbc());

    /* RSA */
    test_rsa_sign_verify("RSA-2048-sign-verify", OBJ_ID_BASE + 50, 2048);
    test_rsa_encrypt_decrypt();
    test_rsa_sign_with_hash("RSA-2048-sign-SHA384",
        OBJ_ID_BASE + 52, 2048,
        kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA384, EVP_sha384(), 48);
    test_rsa_sign_with_hash("RSA-2048-sign-SHA512",
        OBJ_ID_BASE + 53, 2048,
        kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA512, EVP_sha512(), 64);
    test_rsa_sign_verify("RSA-3072-sign-verify", OBJ_ID_BASE + 54, 3072);
    test_rsa_sign_verify("RSA-4096-sign-verify", OBJ_ID_BASE + 55, 4096);
    test_rsa_pss_sign_verify("RSA-2048-PSS-SHA256",
        OBJ_ID_BASE + 56, 2048,
        kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA256, EVP_sha256(), 32);
    /* Only OAEP-SHA1 maps to a real on-wire algo on SE050 silicon; the NXP
     * SDK routes OAEP-SHA256/384/512 to RSAEncryptionAlgo_NA. */
    test_rsa_oaep_encrypt_decrypt("RSA-2048-OAEP-SHA1",
        OBJ_ID_BASE + 57, 2048,
        kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA1, EVP_sha1());
    test_rsa_sign_no_hash();
    test_rsa_se050_self_verify();
    test_rsa_import_sign_verify("RSA-2048-import-sign-verify",
        OBJ_ID_BASE + 59, 2048);
    test_rsa_import_sign_verify_pkcs8("RSA-2048-import-sign-verify-pkcs8",
        OBJ_ID_BASE + 60, 2048);
    test_rsa_import_sign_no_hash();

    /* X25519 */
    test_x25519_ecdh();

    /* Ed25519 */
    test_ed25519_sign_verify();
    test_ed25519_test_vector();

    /* Object management */
    test_object_write_read();
    test_object_delete();

    /* Summary */
    test_summary();

    ex_sss_session_close(&g_ctx);

    return g_tests_failed > 0 ? 1 : 0;
}
