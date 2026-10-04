#define _GNU_SOURCE
#include <curl/curl.h>
#include <dlfcn.h>
#include <link.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PREFIX "/opt/atrinik/tls/"
static int bad_provider;
static int inspect_object(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    (void)data;
    const char *name = strrchr(info->dlpi_name, '/');
    name = name ? name + 1 : info->dlpi_name;
    if (strncmp(name, "libssl.so", 9) == 0 || strncmp(name, "libcrypto.so", 12) == 0 ||
        strncmp(name, "libcurl.so", 10) == 0 || strcmp(name, "legacy.so") == 0) {
        char *path = realpath(info->dlpi_name, NULL);
        if (path == NULL || strncmp(path, PREFIX, sizeof(PREFIX) - 1) != 0) {
            bad_provider = 1;
        }
        free(path);
    }
    return 0;
}
static size_t discard(char *buffer, size_t size, size_t count, void *data) {
    (void)buffer;
    (void)data;
    return size * count;
}
int main(int argc, char **argv) {
    if (argc != 1 && argc != 4) return 2;
    if (strcmp(OPENSSL_VERSION_STR, "4.0.3") != 0 ||
        strcmp(OpenSSL_version(OPENSSL_VERSION_STRING), "4.0.3") != 0) return 3;
    OSSL_PROVIDER *def = OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
    if (def == NULL || legacy == NULL || curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) return 4;
    const curl_version_info_data *version = curl_version_info(CURLVERSION_NOW);
    if (strcmp(version->version, "8.22.0") != 0 || version->ssl_version == NULL ||
        strcmp(version->ssl_version, "OpenSSL/4.0.3") != 0 ||
        !(version->features & CURL_VERSION_SSL) || !(version->features & CURL_VERSION_IDN) ||
        !(version->features & CURL_VERSION_LIBZ)) return 5;
    int http = 0, https = 0;
    for (const char *const *p = version->protocols; *p; ++p) {
        http |= strcmp(*p, "http") == 0;
        https |= strcmp(*p, "https") == 0;
    }
    if (!http || !https) return 6;
    /* Link and exercise the public peer API's fail-closed non-QUIC case. */
    SSL_CTX *context = SSL_CTX_new(TLS_method());
    SSL *ssl = context ? SSL_new(context) : NULL;
    BIO_ADDR *peer = BIO_ADDR_new();
    if (ssl == NULL || peer == NULL || SSL_get_peer_addr(ssl, peer) != 0) return 7;
    BIO_ADDR_free(peer);
    SSL_free(ssl);
    SSL_CTX_free(context);
    dl_iterate_phdr(inspect_object, NULL);
    if (bad_provider) return 8;
    if (argc == 4) {
        CURL *curl = curl_easy_init();
        if (curl == NULL) return 9;
        curl_easy_setopt(curl, CURLOPT_URL, argv[1]);
        curl_easy_setopt(curl, CURLOPT_CAINFO, argv[2]);
        curl_easy_setopt(curl, CURLOPT_PROXY, "");
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard);
        CURLcode result = curl_easy_perform(curl);
        long response = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
        curl_easy_cleanup(curl);
        if (strcmp(argv[3], "trusted") == 0) {
            if (result != CURLE_OK || response != 200) {
                fprintf(stderr, "trusted HTTPS failed: curl=%d (%s), HTTP=%ld\n",
                        (int)result, curl_easy_strerror(result), response);
                return 10;
            }
        } else if (strcmp(argv[3], "untrusted") == 0) {
            if (result != CURLE_PEER_FAILED_VERIFICATION) {
                fprintf(stderr, "untrusted HTTPS was not rejected: curl=%d (%s), HTTP=%ld\n",
                        (int)result, curl_easy_strerror(result), response);
                return 11;
            }
        } else return 12;
    }
    curl_global_cleanup();
    OSSL_PROVIDER_unload(legacy);
    OSSL_PROVIDER_unload(def);
    puts("Classic TLS provider and public peer API checks passed");
    return 0;
}
