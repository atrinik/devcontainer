// SPDX-License-Identifier: MIT
// Copyright 2026 The Atrinik Project
#define _GNU_SOURCE
#include <ares.h>
#include <curl/curl.h>
#include <dlfcn.h>
#include <stdio.h>

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

int main(void) {
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
