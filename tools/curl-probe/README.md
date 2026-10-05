# Classic cancellation producer qualification

`atrinik-curl-cancellation-probe` links the real `Atrinik::Core`
`curl_perform_cancellable` helper from a clean Classic commit. The default is
`66923f8dc65ecbb607df0dd2235517bbca705e3c`; producers can pass a full lowercase
`ATRINIK_CLASSIC_QUALIFICATION_COMMIT` SHA from their committed consumer manifest.
The bridge requires actual Git HEAD and clean tracked source to match that SHA.
The C17 source uses Winsock and a
Windows thread on native Windows, and sockets/pthreads on POSIX. It is a GPL
qualification executable linked with the GPL Classic library; it is not a
replacement implementation of the helper.

Configure the bridge with the producer's normal dependency and toolchain flags:

```sh
cmake -S tools/curl-probe -B build/curl-probe \
  -DATRINIK_CLASSIC_SOURCE_DIR=/absolute/clean/classic
cmake --build build/curl-probe --target atrinik-curl-cancellation-probe
ctest --test-dir build/curl-probe --output-on-failure \
  -R '^atrinik-curl-cancellation-qualification$'
```

For MXE supply the producer's CMake toolchain file during configuration. The
target emits `atrinik-curl-cancellation-probe.exe` on Windows. Bundle its normal
runtime DLL closure, then execute it **natively on Windows** under the runner's
15-second process watchdog. A cross-build or Wine run does not substitute for
native Windows qualification. CTest registers the same watchdog on POSIX.
The bridge can also be added to an existing CMake build that already supplies
`Atrinik::Core`; it verifies that target's source directory against the pinned
checkout before linking. Standalone configuration builds only protocol and
libatrinik, without game targets or unrelated library tests. No downloads are
initiated by this bridge.

Both cases use ephemeral IPv4 loopback ports and disable proxies. DNS injects
only the fixture's UDP server using `CURLOPT_DNS_SERVERS`; the fixture witnesses
a DNS question and never responds. HTTP witnesses complete request headers
and never sends a response. The fixture records its witness time, and a separate
controller publishes cancellation at that time plus 100 ms, independently of
when the helper polls its callback. Each case requires
`CURLE_ABORTED_BY_CALLBACK` and at most 1000 ms from that scheduled cancellation
through helper return (including multi cleanup), easy/global cleanup, and both
controller and fixture stops/joins. The fixture stays alive throughout transfer
cleanup and is then explicitly stopped and joined. A missing witness cancels after three
seconds to keep failure bounded, but always fails qualification. Transfer
timeouts are ten seconds, so a timeout result cannot pass. All cleanup runs
normally; there is no forced process exit or quick-exit success path.

The executable rejects runtime providers other than curl 8.18.0 or 8.21.0,
c-ares 1.34.6 and `OpenSSL/3.5.5`, including OpenSSL 4. The output records the
runtime curl/c-ares/OpenSSL versions, each fixture witness,
result, cleanup duration, deadline and PASS/FAIL. The producer must separately
verify generated curl configuration, header/runtime/provider identity and
DLL imports: ASYNCHDNS or a c-ares version alone cannot qualify the backend.
Keep the producer's pinned OpenSSL 3.5.5 provider and dependency closure.

Native Windows public-CA qualification is a separate invocation:

```sh
atrinik-curl-cancellation-probe.exe --public-ca ca-bundle.crt https://curl.se/
```

Use the exact Classic client bundle and verify its manifest hash before invoking
the probe. This mode admits only that fixed endpoint, explicitly enables peer
and hostname verification, sets `CAINFO` to the supplied bundle, clears `CAPATH`,
disables redirects/proxies, discards response data, and requires a successful
2xx response with verification result zero. Transfer/connect timeouts and the
independent cancellation deadline are ten seconds; complete cleanup and joining
must finish within an additional second. Diagnostics include only the fixed
origin hostname, status, verification result, provider and timing. A missing,
empty, malformed or untrusted CA bundle must fail; the same command with a
nonempty invalid bundle can be used as a negative check. This real TLS request
requires network access and is separate from loopback cancellation qualification.
