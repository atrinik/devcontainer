// SPDX-License-Identifier: MIT
// Copyright 2026 The Atrinik Project
#define _GNU_SOURCE
#include <ares.h>
#include <curl/curl.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

static void string(const char *value) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        if (*p == '"' || *p == '\\') putchar('\\');
        if (*p < 32) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}

static void array(const char *const *values) {
    putchar('[');
    for (size_t i = 0; values[i]; ++i) {
        if (i) putchar(',');
        string(values[i]);
    }
    putchar(']');
}

static size_t discard(char *data, size_t size, size_t count, void *context) {
    (void)data; (void)context;
    return size * count;
}

static int public_ca(const char *bundle, int untrusted) {
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) return 1;
    CURL *easy = curl_easy_init();
    if (!easy) { curl_global_cleanup(); return 1; }
    int configured = 1;
#define SET(option, value) do { if (curl_easy_setopt(easy, option, value) != CURLE_OK) configured = 0; } while (0)
    SET(CURLOPT_URL, "https://curl.se/");
    SET(CURLOPT_PROXY, "");
    SET(CURLOPT_NOPROXY, "*");
    SET(CURLOPT_NETRC, CURL_NETRC_IGNORED);
    SET(CURLOPT_SSL_VERIFYPEER, 1L);
    SET(CURLOPT_SSL_VERIFYHOST, 2L);
    SET(CURLOPT_CAINFO, bundle);
    SET(CURLOPT_CAPATH, NULL);
    SET(CURLOPT_FOLLOWLOCATION, 0L);
    SET(CURLOPT_NOSIGNAL, 1L);
    SET(CURLOPT_TIMEOUT_MS, 10000L);
    SET(CURLOPT_CONNECTTIMEOUT_MS, 10000L);
    SET(CURLOPT_WRITEFUNCTION, discard);
#undef SET
    CURLcode result = configured ? curl_easy_perform(easy) : CURLE_FAILED_INIT;
    long status = 0, verification = -1;
    int info = curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &status) == CURLE_OK &&
               curl_easy_getinfo(easy, CURLINFO_SSL_VERIFYRESULT, &verification) == CURLE_OK;
    int passed = configured && info && (untrusted ?
        result == CURLE_PEER_FAILED_VERIFICATION && verification != 0 :
        result == CURLE_OK && verification == 0 && status >= 200 && status < 400);
    printf("{\"origin\":\"curl.se\",\"status\":%ld,\"verification\":%ld,\"result\":%d,\"expected_untrusted\":%s,\"passed\":%s}\n",
           status, verification, (int)result, untrusted ? "true" : "false", passed ? "true" : "false");
    curl_easy_cleanup(easy);
    curl_global_cleanup();
    return passed ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc == 3 && (!strcmp(argv[1], "--public-ca") || !strcmp(argv[1], "--untrusted-ca")))
        return public_ca(argv[2], !strcmp(argv[1], "--untrusted-ca"));
    if (argc != 1) return 1;
    const curl_version_info_data *info = curl_version_info(CURLVERSION_NOW);
    Dl_info curl, cares;
    if (!info || info->age < CURLVERSION_ELEVENTH || !info->feature_names || !info->ares ||
        !dladdr((void *)curl_version_info, &curl) || !dladdr((void *)ares_version, &cares)) return 1;
    printf("{\"header_version\":"); string(LIBCURL_VERSION);
    printf(",\"cares_header_version\":"); string(ARES_VERSION_STR);
    printf(",\"runtime_version\":"); string(curl_version());
    printf(",\"curl_path\":"); string(curl.dli_fname);
    printf(",\"cares_path\":"); string(cares.dli_fname);
    printf(",\"cares_version\":"); string(ares_version(NULL));
    printf(",\"protocols\":"); array(info->protocols);
    printf(",\"features\":"); array(info->feature_names);
    puts("}");
    return 0;
}
