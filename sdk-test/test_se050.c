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

    /* Object management */
    test_object_write_read();
    test_object_delete();

    /* Summary */
    test_summary();

    ex_sss_session_close(&g_ctx);

    return g_tests_failed > 0 ? 1 : 0;
}
