# Classic cancellation producer qualification

`atrinik-curl-cancellation-probe` links the real `Atrinik::Core`
`curl_perform_cancellable` helper from the clean Classic commit
`cf79a590dd9789e8a6b6e1fbd57d7f5110845e05`. The C17 source uses Winsock and a
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
and never sends a response. Cancellation begins after that witness and a
100-ms stall. Each case requires `CURLE_ABORTED_BY_CALLBACK` and at most 1000 ms
from cancellation through helper return (including multi cleanup), easy
cleanup and global cleanup. The fixture stays alive throughout cleanup and is
then explicitly stopped and joined. A missing witness cancels after three
seconds to keep failure bounded, but always fails qualification. Transfer
timeouts are ten seconds, so a timeout result cannot pass. All cleanup runs
normally; there is no forced process exit or quick-exit success path.

The output records the runtime curl/c-ares versions, each fixture witness,
result, cleanup duration, deadline and PASS/FAIL. The producer must separately
verify generated curl configuration, header/runtime/provider identity and
DLL imports: ASYNCHDNS or a c-ares version alone cannot qualify the backend.
Keep the producer's pinned OpenSSL 3.5.5 provider and dependency closure.
