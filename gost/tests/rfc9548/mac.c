/*
 * Проверка MAC эталонных контейнеров PKCS#12 из RFC 9548 (приложение A):
 * HMAC-GOST R 34.11-2012 (512 бит) с ключом, выработанным PBKDF2.
 *
 * Программа линкуется со статическими libcrypto и gostprov и регистрирует
 * gostprov как встроенный провайдер — так же, как это делает колесо.
 *
 * Использование: rfc9548-mac ПАРОЛЬ ФАЙЛ.pfx...
 * Код возврата 0, если MAC сходится у всех файлов.
 */
#include <stdio.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/provider.h>

extern OSSL_provider_init_fn GOST_provider_init;

int main(int argc, char **argv)
{
    int i, failed = 0;

    if (argc < 3) {
        fprintf(stderr, "usage: %s PASSWORD FILE.pfx...\n", argv[0]);
        return 2;
    }
    if (!OSSL_PROVIDER_add_builtin(NULL, "gostprov", GOST_provider_init)
        || OSSL_PROVIDER_load(NULL, "default") == NULL
        || OSSL_PROVIDER_load(NULL, "gostprov") == NULL) {
        ERR_print_errors_fp(stderr);
        return 2;
    }

    for (i = 2; i < argc; i++) {
        BIO *bio = BIO_new_file(argv[i], "rb");
        PKCS12 *p12 = bio != NULL ? d2i_PKCS12_bio(bio, NULL) : NULL;
        int ok = p12 != NULL && PKCS12_verify_mac(p12, argv[1], -1);

        printf("%s: MAC %s\n", argv[i], ok ? "OK" : "FAIL");
        if (!ok) {
            ERR_print_errors_fp(stderr);
            failed = 1;
        }
        PKCS12_free(p12);
        BIO_free(bio);
    }
    return failed;
}
