/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright 2026 The Atrinik Project
 * Qualification executable linked with Classic Atrinik::Core.
 */
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
typedef SOCKET probe_socket_t;
typedef HANDLE probe_thread_t;
#define PROBE_INVALID INVALID_SOCKET
#define probe_close closesocket
#else
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
typedef int probe_socket_t;
typedef pthread_t probe_thread_t;
#define PROBE_INVALID (-1)
#define probe_close close
#endif

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <toolkit/curl.h>

enum { FIXTURE_WAIT_MS = 3000, CANCEL_DELAY_MS = 100, CLEANUP_LIMIT_MS = 1000 };

typedef struct fixture {
    probe_socket_t listener;
    bool dns;
    atomic_bool stop;
    atomic_uint_fast64_t received_ms;
    atomic_bool failed;
} fixture_t;

typedef struct cancellation {
    fixture_t *fixture;
    uint64_t started_ms;
    unsigned timeout_ms;
    atomic_bool stop;
    atomic_uint_fast64_t cancelled_ms;
} cancellation_t;

static uint64_t monotonic_ms(void) {
#ifdef _WIN32
    /* QPC works on the supported native Windows toolchain without depending
     * on the legacy WINVER selected by Classic's porting header. */
    LARGE_INTEGER now, frequency;
    QueryPerformanceCounter(&now);
    QueryPerformanceFrequency(&frequency);
    return (uint64_t)(now.QuadPart / frequency.QuadPart) * 1000U +
           (uint64_t)(now.QuadPart % frequency.QuadPart) * 1000U /
               (uint64_t)frequency.QuadPart;
#else
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
#endif
}

static void sleep_ms(unsigned milliseconds) {
#ifdef _WIN32
    Sleep(milliseconds);
#else
    struct timespec delay = {.tv_sec = milliseconds / 1000U,
                             .tv_nsec = (long)(milliseconds % 1000U) * 1000000L};
    nanosleep(&delay, NULL);
#endif
}

static void fixture_received(fixture_t *fixture) {
    uint_fast64_t expected = 0;
    atomic_compare_exchange_strong(&fixture->received_ms, &expected, monotonic_ms());
}

/* All sockets have one owner, and reads happen only after readiness. The
 * short select timeout is the fixture's explicit cooperative stop event. */
static int readable(probe_socket_t socket_handle) {
    fd_set readers;
    FD_ZERO(&readers);
    FD_SET(socket_handle, &readers);
    struct timeval timeout = {.tv_sec = 0, .tv_usec = 20000};
#ifdef _WIN32
    return select(0, &readers, NULL, NULL, &timeout);
#else
    return select(socket_handle + 1, &readers, NULL, NULL, &timeout);
#endif
}

#ifdef _WIN32
static DWORD WINAPI fixture_run(LPVOID context) {
#else
static void *fixture_run(void *context) {
#endif
    fixture_t *fixture = context;
    probe_socket_t client = PROBE_INVALID;
    char request[8192];
    size_t used = 0;
    while (!atomic_load(&fixture->stop)) {
        probe_socket_t active = client != PROBE_INVALID ? client : fixture->listener;
        int ready = readable(active);
        if (ready < 0) {
            atomic_store(&fixture->failed, true);
            break;
        }
        if (ready == 0)
            continue;
        if (!fixture->dns && client == PROBE_INVALID) {
            client = accept(fixture->listener, NULL, NULL);
            if (client == PROBE_INVALID) {
                atomic_store(&fixture->failed, true);
                break;
            }
#ifndef _WIN32
            if (client >= FD_SETSIZE) {
                atomic_store(&fixture->failed, true);
                break;
            }
#endif
            continue;
        }
        int received = recv(active, request + used, (int)(sizeof(request) - used - 1), 0);
        if (received <= 0) {
            /* EOF after cancellation is expected, but it cannot qualify an
             * HTTP fixture which never saw a complete request. */
            if (!atomic_load(&fixture->received_ms))
                atomic_store(&fixture->failed, true);
            break;
        }
        if (fixture->dns) {
            /* A DNS question has a header, QR=0, and a nonzero QDCOUNT.
             * Silently discard it: no DNS response or fallback server. */
            if (received >= 12 && !((unsigned char)request[2] & 0x80) &&
                ((unsigned char)request[4] || (unsigned char)request[5]))
                fixture_received(fixture);
            continue;
        }
        used += (size_t)received;
        request[used] = '\0';
        if (strstr(request, "\r\n\r\n") != NULL) {
            if (strncmp(request, "GET /cancel-probe HTTP/", 23) == 0)
                fixture_received(fixture);
            else
                atomic_store(&fixture->failed, true);
            /* Continue waiting without sending any HTTP response. */
            used = 0;
        } else if (used == sizeof(request) - 1) {
            atomic_store(&fixture->failed, true);
            break;
        }
    }
    if (client != PROBE_INVALID)
        probe_close(client);
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

static bool fixture_start(fixture_t *fixture, bool dns, unsigned *port, probe_thread_t *thread) {
    memset(fixture, 0, sizeof(*fixture));
    atomic_init(&fixture->stop, false);
    atomic_init(&fixture->received_ms, 0);
    atomic_init(&fixture->failed, false);
    fixture->dns = dns;
    fixture->listener = socket(AF_INET, dns ? SOCK_DGRAM : SOCK_STREAM, 0);
    if (fixture->listener == PROBE_INVALID)
        return false;
#ifndef _WIN32
    if (fixture->listener >= FD_SETSIZE) {
        probe_close(fixture->listener);
        return false;
    }
#endif
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#ifdef _WIN32
    int size = sizeof(address);
#else
    socklen_t size = sizeof(address);
#endif
    if (bind(fixture->listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        (!dns && listen(fixture->listener, 1) != 0) ||
        getsockname(fixture->listener, (struct sockaddr *)&address, &size) != 0) {
        probe_close(fixture->listener);
        return false;
    }
    *port = ntohs(address.sin_port);
#ifdef _WIN32
    *thread = CreateThread(NULL, 0, fixture_run, fixture, 0, NULL);
    bool started = *thread != NULL;
#else
    bool started = pthread_create(thread, NULL, fixture_run, fixture) == 0;
#endif
    if (!started)
        probe_close(fixture->listener);
    return started;
}

static bool fixture_stop(fixture_t *fixture, probe_thread_t thread) {
    atomic_store(&fixture->stop, true);
#ifdef _WIN32
    bool joined = WaitForSingleObject(thread, INFINITE) == WAIT_OBJECT_0;
    CloseHandle(thread);
#else
    bool joined = pthread_join(thread, NULL) == 0;
#endif
    probe_close(fixture->listener);
    return joined;
}

#ifdef _WIN32
static DWORD WINAPI cancellation_run(LPVOID context) {
#else
static void *cancellation_run(void *context) {
#endif
    cancellation_t *cancel = context;
    while (!atomic_load(&cancel->stop)) {
        uint64_t scheduled_ms = cancel->started_ms + cancel->timeout_ms;
        if (cancel->fixture != NULL) {
            uint64_t received_ms = atomic_load(&cancel->fixture->received_ms);
            if (received_ms != 0 && received_ms + CANCEL_DELAY_MS < scheduled_ms)
                scheduled_ms = received_ms + CANCEL_DELAY_MS;
        }
        if (monotonic_ms() >= scheduled_ms) {
            /* Publish the scheduled deadline, not when the helper next polls
             * or when this controller happens to be scheduled by the OS. */
            atomic_store(&cancel->cancelled_ms, scheduled_ms);
            break;
        }
        sleep_ms(1);
    }
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

static bool cancellation_start(cancellation_t *cancel, fixture_t *fixture,
                               unsigned timeout_ms, probe_thread_t *thread) {
    cancel->fixture = fixture;
    cancel->started_ms = monotonic_ms();
    cancel->timeout_ms = timeout_ms;
    atomic_init(&cancel->stop, false);
    atomic_init(&cancel->cancelled_ms, 0);
#ifdef _WIN32
    *thread = CreateThread(NULL, 0, cancellation_run, cancel, 0, NULL);
    return *thread != NULL;
#else
    return pthread_create(thread, NULL, cancellation_run, cancel) == 0;
#endif
}

static bool cancellation_stop(cancellation_t *cancel, probe_thread_t thread) {
    atomic_store(&cancel->stop, true);
#ifdef _WIN32
    bool joined = WaitForSingleObject(thread, INFINITE) == WAIT_OBJECT_0;
    CloseHandle(thread);
    return joined;
#else
    return pthread_join(thread, NULL) == 0;
#endif
}

static bool cancelled(void *context) {
    cancellation_t *cancel = context;
    return atomic_load(&cancel->cancelled_ms) != 0;
}

static bool qualify(bool dns) {
    fixture_t fixture;
    probe_thread_t thread;
    unsigned port;
    if (!fixture_start(&fixture, dns, &port, &thread)) {
        fprintf(stderr, "%s fixture failed to start\n", dns ? "DNS" : "HTTP");
        return false;
    }
    bool initialized = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
    CURL *easy = initialized ? curl_easy_init() : NULL;
    char url[128], dns_server[64];
    snprintf(url, sizeof(url), dns ? "http://cancel-probe.invalid/cancel-probe" :
             "http://127.0.0.1:%u/cancel-probe", port);
    snprintf(dns_server, sizeof(dns_server), "127.0.0.1:%u", port);
    bool configured = easy != NULL;
#define CONFIGURE(option, value) \
    do { if (configured && curl_easy_setopt(easy, option, value) != CURLE_OK) \
        configured = false; } while (0)
    CONFIGURE(CURLOPT_URL, url);
    CONFIGURE(CURLOPT_PROXY, "");
    CONFIGURE(CURLOPT_NOPROXY, "*");
    CONFIGURE(CURLOPT_NOSIGNAL, 1L);
    CONFIGURE(CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
    CONFIGURE(CURLOPT_DNS_CACHE_TIMEOUT, 0L);
    CONFIGURE(CURLOPT_TIMEOUT_MS, 10000L);
    CONFIGURE(CURLOPT_CONNECTTIMEOUT_MS, 10000L);
    if (dns)
        CONFIGURE(CURLOPT_DNS_SERVERS, dns_server);
#undef CONFIGURE
    cancellation_t state;
    probe_thread_t controller;
    bool controller_started = cancellation_start(&state, &fixture, FIXTURE_WAIT_MS, &controller);
    configured = configured && controller_started;
    curl_cancel_t cancel = {.cancelled = cancelled, .context = &state};
    CURLcode result = configured ? curl_perform_cancellable(easy, &cancel) : CURLE_FAILED_INIT;
    /* Helper return includes remove_handle and multi_cleanup. Measure through
     * easy/global cleanup while the fixtures remain stalled and alive. */
    if (easy != NULL)
        curl_easy_cleanup(easy);
    if (initialized)
        curl_global_cleanup();
    bool controller_joined = controller_started && cancellation_stop(&state, controller);
    bool joined = fixture_stop(&fixture, thread);
    uint64_t finished_ms = monotonic_ms();
    uint64_t received_ms = atomic_load(&fixture.received_ms);
    uint64_t cancelled_ms = atomic_load(&state.cancelled_ms);
    bool received = received_ms != 0;
    bool failed = atomic_load(&fixture.failed);
    uint64_t elapsed = cancelled_ms == 0 ? UINT64_MAX : finished_ms - cancelled_ms;
    bool passed = configured && received && !failed && joined && controller_joined &&
                  cancelled_ms == received_ms + CANCEL_DELAY_MS &&
                  result == CURLE_ABORTED_BY_CALLBACK && elapsed <= CLEANUP_LIMIT_MS;
    printf("%s fixture_received=%d result=%d cancel_to_cleanup_ms=%llu limit_ms=%d %s\n",
           dns ? "stalled_dns" : "stalled_http", received, (int)result,
           (unsigned long long)elapsed, CLEANUP_LIMIT_MS, passed ? "PASS" : "FAIL");
    return passed;
}

static size_t discard_response(char *data, size_t size, size_t count, void *context) {
    (void)data;
    (void)context;
    return size * count;
}

static bool qualify_public_ca(const char *bundle) {
    /* This mode intentionally admits only the declared public qualification
     * endpoint. Neither CA contents nor URL paths enter diagnostics. */
    FILE *ca = fopen(bundle, "rb");
    if (ca == NULL) {
        fprintf(stderr, "Public-CA bundle is unreadable\n");
        return false;
    }
    bool nonempty = fgetc(ca) != EOF;
    fclose(ca);
    if (!nonempty) {
        fprintf(stderr, "Public-CA bundle is empty\n");
        return false;
    }
    bool initialized = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
    CURL *easy = initialized ? curl_easy_init() : NULL;
    bool configured = easy != NULL;
#define CONFIGURE(option, value) \
    do { if (configured && curl_easy_setopt(easy, option, value) != CURLE_OK) \
        configured = false; } while (0)
    CONFIGURE(CURLOPT_URL, "https://curl.se/");
    CONFIGURE(CURLOPT_PROXY, "");
    CONFIGURE(CURLOPT_NOPROXY, "*");
    CONFIGURE(CURLOPT_NOSIGNAL, 1L);
    CONFIGURE(CURLOPT_SSL_VERIFYPEER, 1L);
    CONFIGURE(CURLOPT_SSL_VERIFYHOST, 2L);
    CONFIGURE(CURLOPT_CAINFO, bundle);
    CONFIGURE(CURLOPT_CAPATH, NULL);
    CONFIGURE(CURLOPT_FOLLOWLOCATION, 0L);
    CONFIGURE(CURLOPT_TIMEOUT_MS, 10000L);
    CONFIGURE(CURLOPT_CONNECTTIMEOUT_MS, 10000L);
    CONFIGURE(CURLOPT_WRITEFUNCTION, discard_response);
#undef CONFIGURE
    cancellation_t state;
    probe_thread_t controller;
    bool started = cancellation_start(&state, NULL, 10000, &controller);
    configured = configured && started;
    curl_cancel_t cancel = {.cancelled = cancelled, .context = &state};
    CURLcode result = configured ? curl_perform_cancellable(easy, &cancel) : CURLE_FAILED_INIT;
    long status = 0, verification = -1;
    bool info = easy != NULL &&
                curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &status) == CURLE_OK &&
                curl_easy_getinfo(easy, CURLINFO_SSL_VERIFYRESULT, &verification) == CURLE_OK;
    if (easy != NULL)
        curl_easy_cleanup(easy);
    if (initialized)
        curl_global_cleanup();
    bool joined = started && cancellation_stop(&state, controller);
    uint64_t duration_ms = monotonic_ms() - state.started_ms;
    bool passed = configured && joined && info && result == CURLE_OK && verification == 0 &&
                  status >= 200 && status < 300 && duration_ms <= 11000;
    printf("public_ca origin=curl.se status=%ld verification=%ld result=%d elapsed_ms=%llu %s\n",
           status, verification, (int)result, (unsigned long long)duration_ms,
           passed ? "PASS" : "FAIL");
    return passed;
}

int main(int argc, char **argv) {
    bool public_ca = argc == 4 && strcmp(argv[1], "--public-ca") == 0 &&
                     strcmp(argv[3], "https://curl.se/") == 0;
    if (argc != 1 && !public_ca) {
        fprintf(stderr, "Usage: atrinik-curl-cancellation-probe [--public-ca BUNDLE https://curl.se/]\n");
        return 1;
    }
#ifdef _WIN32
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
        return 1;
#endif
    const curl_version_info_data *version = curl_version_info(CURLVERSION_NOW);
    if (version == NULL || version->ares == NULL || version->ssl_version == NULL ||
        !(version->features & CURL_VERSION_ASYNCHDNS) ||
        (strcmp(version->version, "8.18.0") != 0 && strcmp(version->version, "8.21.0") != 0) ||
        strcmp(version->ares, "1.34.6") != 0 || strcmp(version->ssl_version, "OpenSSL/3.5.5") != 0) {
        fprintf(stderr, "Qualification requires curl 8.18.0/8.21.0, c-ares 1.34.6 and OpenSSL/3.5.5\n");
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
    printf("Atrinik::Core qualification curl=%s c-ares=%s ssl=%s\n",
           version->version, version->ares, version->ssl_version);
    bool passed;
    if (public_ca) {
        passed = qualify_public_ca(argv[2]);
    } else {
        bool dns_passed = qualify(true);
        bool http_passed = qualify(false);
        passed = dns_passed && http_passed;
    }
#ifdef _WIN32
    WSACleanup();
#endif
    return passed ? 0 : 1;
}
