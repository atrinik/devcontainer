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
    atomic_bool received;
    atomic_bool failed;
} fixture_t;

typedef struct cancellation {
    fixture_t *fixture;
    uint64_t started_ms;
    uint64_t received_ms;
    uint64_t cancelled_ms;
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
            if (!atomic_load(&fixture->received))
                atomic_store(&fixture->failed, true);
            break;
        }
        if (fixture->dns) {
            /* A DNS question has a header, QR=0, and a nonzero QDCOUNT.
             * Silently discard it: no DNS response or fallback server. */
            if (received >= 12 && !((unsigned char)request[2] & 0x80) &&
                ((unsigned char)request[4] || (unsigned char)request[5]))
                atomic_store(&fixture->received, true);
            continue;
        }
        used += (size_t)received;
        request[used] = '\0';
        if (strstr(request, "\r\n\r\n") != NULL) {
            if (strncmp(request, "GET /cancel-probe HTTP/", 23) == 0)
                atomic_store(&fixture->received, true);
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
    atomic_init(&fixture->received, false);
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

static bool cancelled(void *context) {
    cancellation_t *cancel = context;
    uint64_t now = monotonic_ms();
    if (atomic_load(&cancel->fixture->received) && cancel->received_ms == 0)
        cancel->received_ms = now;
    bool should_cancel = (cancel->received_ms != 0 &&
                          now - cancel->received_ms >= CANCEL_DELAY_MS) ||
                         now - cancel->started_ms >= FIXTURE_WAIT_MS;
    if (should_cancel && cancel->cancelled_ms == 0)
        cancel->cancelled_ms = now;
    return should_cancel;
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
    cancellation_t state = {.fixture = &fixture, .started_ms = monotonic_ms()};
    curl_cancel_t cancel = {.cancelled = cancelled, .context = &state};
    CURLcode result = configured ? curl_perform_cancellable(easy, &cancel) : CURLE_FAILED_INIT;
    /* Helper return includes remove_handle and multi_cleanup. Measure through
     * easy/global cleanup while the fixtures remain stalled and alive. */
    if (easy != NULL)
        curl_easy_cleanup(easy);
    if (initialized)
        curl_global_cleanup();
    uint64_t finished_ms = monotonic_ms();
    bool received = atomic_load(&fixture.received);
    bool failed = atomic_load(&fixture.failed);
    bool joined = fixture_stop(&fixture, thread);
    uint64_t elapsed = state.cancelled_ms == 0 ? UINT64_MAX : finished_ms - state.cancelled_ms;
    bool passed = configured && received && !failed && joined && state.received_ms != 0 &&
                  result == CURLE_ABORTED_BY_CALLBACK && elapsed <= CLEANUP_LIMIT_MS;
    printf("%s fixture_received=%d result=%d cancel_to_cleanup_ms=%llu limit_ms=%d %s\n",
           dns ? "stalled_dns" : "stalled_http", received, (int)result,
           (unsigned long long)elapsed, CLEANUP_LIMIT_MS, passed ? "PASS" : "FAIL");
    return passed;
}

int main(void) {
#ifdef _WIN32
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
        return 1;
#endif
    const curl_version_info_data *version = curl_version_info(CURLVERSION_NOW);
    if (version == NULL || version->ares == NULL || !(version->features & CURL_VERSION_ASYNCHDNS)) {
        fprintf(stderr, "Qualification requires the producer's c-ares libcurl\n");
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
    printf("Atrinik::Core cancellation qualification curl=%s c-ares=%s\n", version->version, version->ares);
    bool dns_passed = qualify(true);
    bool http_passed = qualify(false);
#ifdef _WIN32
    WSACleanup();
#endif
    return dns_passed && http_passed ? 0 : 1;
}
