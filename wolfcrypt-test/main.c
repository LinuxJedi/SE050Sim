/*
 * Standalone wolfCrypt test with SE050 simulator initialization.
 */

#include <stdio.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/port/nxp/se050_port.h>

/* wolfcrypt_test defined in test.c */
int wolfcrypt_test(void* args);

int main(void)
{
    int ret;

    printf("=== Initializing SE050 Simulator Connection ===\n");
    fflush(stdout);

    ret = wc_se050_init(NULL);
    if (ret != 0) {
        printf("ERROR: wc_se050_init() failed with %d\n", ret);
        return -1;
    }

    printf("=== SE050 Connection Established ===\n");
    fflush(stdout);

    wolfSSL_Init();

    printf("=== Calling wolfcrypt_test... ===\n");
    fflush(stdout);
    fflush(stderr);

    ret = wolfcrypt_test(NULL);

    fflush(stdout);
    fflush(stderr);
    wolfSSL_Cleanup();

    printf("\n=== wolfCrypt Test %s (return code: %d) ===\n",
           ret == 0 ? "PASSED" : "FAILED", ret);

    return ret;
}
