# Released portable SDK inventory qualification

`released_sdk_inventory.py` is an internal acquisition helper for the existing
collector's authenticated, task-owned `StoppedImage` and archive protocol. It
has no CLI, credentials, registry operations, release pins or image execution.
The collector imports it through an explicit same-checkout path under isolated
Python. Only its internal final-target path invokes inventory and execution;
`portable-final` pins the reviewed 1.22.0 release. The three fixed 1.18.0
targets and their producer mapping remain unchanged; final targets cannot use
the historical producer-policy fallback.

The helper streams `/opt/atrinik-portable` without extraction. It retains only
the fixed `audio-toolchain.json`, `llvm-toolchain.json`, `curl-toolchain.json`
and `classic-curl-toolchain.json` payloads, each nonempty
and at most 1 MiB, as private validation inputs on `ProducerInventory`. Before
parsing a manifest, it binds the retained bytes to the streamed record's
SHA-256 and size. These payloads are excluded from serialized inventory maps and
their digests; copying the records to a plain dictionary loses the payloads and
fails closed during source-archive validation. All other file payloads are
discarded after hashing. It requires a root directory entry, parents before children, unique
canonical relative paths, regular files and safe directory/file modes. It
rejects links, special/sparse files, path/size PAX overrides, malformed headers,
truncated members, missing end markers and nonzero trailing data. Timestamp-only
PAX records are accepted. Bounds are 20,000 members, 1,024-byte paths, 1 GiB per
file, 8 GiB aggregate payload and a shared 900-second deadline; single-file
reads use the same deadline and aggregate accounting. The existing collector's
operation alarm and socket timeout remain required outer bounds.

On a failed whole-path-stat comparison, `inventory_failure.path_stat_drift`
records the fixed comparison site (`directory-header`, `producer-header`,
`regular-header` or `recheck`), a fixed subject class (`root-directory`,
`directory` or `file`), changed known field names (`name`, `size`, `mode`,
`mtime`, `linkTarget`), and booleans for field-set and unknown-field changes.
It never retains stat values, arbitrary field names, paths or exception text.
Every nonroot path retains full stat equality, including timestamps, sizes and
unknown fields, before inventories or scanner qualification can succeed.

Moby Docker 29.4.2 opens a new filesystem view for each
[`HEAD` or `GET` archive operation](https://github.com/moby/moby/blob/docker-v29.4.2/daemon/archive_unix.go).
Its [`filesystem view`](https://github.com/moby/moby/blob/docker-v29.4.2/daemon/containerfs_linux.go)
calls [`SwitchRoot`](https://github.com/moby/moby/blob/docker-v29.4.2/daemon/internal/mounttree/switchroot_linux.go),
which can create and remove a temporary directory directly beneath the root.
The resulting root `mtime` is specific to that filesystem view. Root `size` is
the raw `lstat.Size()` of the directory: Go documents nonregular-file size as
[system-dependent](https://go.dev/src/io/fs/fs.go), and Linux directories store
[directory entries in filesystem data blocks](https://docs.kernel.org/filesystems/ext4/directory.html).
Creating/removing a directory entry does not guarantee restoring that storage
size. This differs from the root tar header's required zero payload size.

Only the exact `/` path uses a separate metadata fence. Both root stats must
have exactly `name`, `size`, `mode`, `mtime` and `linkTarget`; unknown or absent
fields fail even when both snapshots agree. Name must be `/`, link target must
be empty, and mode must be a true integer containing only the Go directory bit
and safe permissions. These fields remain exactly equal across views. Size must
be a true integer in `0..2^63-1`; mtime must be a valid calendar timestamp in
RFC3339Nano form (years 1–9999, at most nine fractional digits, explicit UTC or
numeric offset). These two view-local fields are validated but not compared for
equality at `/`. This exception never applies to any other path.

Protected reads retain the exact created-container identity, selected image,
mount, read-only and network isolation fences before and after reading bytes.
Root ownership is checked through a bounded GET header both before and after
the protected read: exact `/` name, directory type, matching mode, UID 0 and
zero tar payload size. Each stream closes after the header. The existing GID
policy is unchanged. All provider/tool bytes and nonroot ancestor stats remain
fenced, and the separate scanner must still prove complete inventory equality.

The Moby source proves that root timestamp equality is an invalid cross-view
invariant. It does not establish the actual comparison site or changed field
in a hosted failure whose stats were not retained. Source-derived fixtures and
diagnostics do not qualify the released SDK; actual hosted collection and
filesystem equality remain required.

Each producer record is `relative_path -> {sha256, size, executable}`, including
zero-byte files. Canonical sorted compact JSON uses the wrapper's
`linux_portable.inventory_digest` format. Common licenses use exactly the
wrapper's fourteen fixed names. Debian notices are selected only by matching
`runtime-sources.json.source_packages` to `debian-sources.json` package/source
rows. Their records retain the requested absolute path as key and add
`resolved_path`. Source archives named by the authenticated runtime and contract
documents must match the complete producer inventory, including custom provider
archives and the audio and LLVM archives declared by their referenced manifests.
Every declared archive record requires an integer size greater than zero and at
most 1 GiB, plus the declared SHA-256; even the matching digest of an empty file
cannot satisfy an archive declaration.
Debian notices, common licenses and build-tool executables must be nonempty;
other producer-tree files may legitimately have zero bytes.

Archive validation requires the schema-2 `portable-final`, `linux/amd64`
contract, including the fixed audio, LLVM and curl manifest references. The
curl manifest must reference the fixed shared Classic curl manifest. Historical
contracts with absent references cannot qualify through this helper. The
contract's source cohort is exactly `openssl`, `sdl3`, `sdl3-image` and
`sdl3-ttf`; the audio cohort is `SDL3_mixer` with `libogg`, `libopus` and
`libopusfile`. Missing, duplicate or renamed components fail validation.
`runtime-sources.json.custom_providers` must contain exactly `libcurl` and
`libcares`, with the fields emitted by `portable/legal.py`. Their complete
archive maps must match the authenticated curl manifests: the four Debian
curl source/signature files under `sources/curl/`, and the digest-named c-ares
archive under `sources/`. Removing an individual archive from a provider's
declaration cannot bypass its byte check. These checks validate declared source
closure; they do not parse Debian `.dsc` dependency semantics or independently
establish completeness of the producer's Debian source-package archive map.

Docker HEAD's `LinkTarget` is a fully resolved result, so it cannot establish a
safe link traversal by itself. The notice resolver reads each raw symbolic link
as a single tar member, resolves at most sixteen hops itself beneath
`/usr/share/doc`, rejects even temporary escape and cycles, and crosschecks the
result against HEAD. Parent (`..`) components are accepted only at the start
of a relative link target, before any potentially symbolic component. It
rechecks raw links, canonical regular files and every
observed parent/root before returning. This relies on Moby's
[`containerArchivePath`](https://github.com/moby/moby/blob/v28.5.1/daemon/archive_unix.go)
and [`containerFSView.Stat`](https://github.com/moby/moby/blob/v28.5.1/daemon/containerfs_linux.go)
semantics; final hosted qualification must exercise the actual daemon. The
producer-tree path accepts no links at all. Docker tar generation may omit entries
when traversal fails: complete tar framing proves only the delivered stream.
Before adopting new wrapper pins, final hosted qualification must independently
compare this producer map with the wrapper's `verified_tree_inventory` on that
exact image (or an authenticated complete OCI-overlay reconstruction). Source
archive hash checks alone do not establish that no unrelated file was omitted.

The build-tool reader requires exactly `cmake`, `ninja` and `pkg_config` at
`/usr/bin/cmake`, `/usr/bin/ninja` and `/usr/bin/pkgconf`, all canonical regular
executables. `pkg_config` uses the numeric version grammar shared with Ninja;
the `pkg-config` alias cannot substitute for the fixed `pkgconf` path. It validates
`installed.json.build_tools = {schema_version: 1, tools: {…}}`, the exact role and
field sets, full producer version strings and legacy first-line compatibility,
then compares streamed bytes, size and executable status. It never executes a
tool to obtain a version. LLVM compiler evidence retains its separate roles.

The collector's internal final path now binds every retained portable metadata
file to the producer map, checks corresponding source and shader-input hashes,
passes that same authenticated `InstalledInventory` reader to source/provider
closure validation, checks the consumer in both contract and shader record, retains all twelve LLVM
roles, and acquires the three build-tool identities. It writes complete
`inventories/{producer,debian_notices,common_licenses}.json` artifacts, canonical
map digests and seven metadata hashes. Saved acquisition receipts retain
`installed-identity-only`, `image_code_executed: false` and
`final_portable_cohort: false`; those fields describe its created-only acquisition
container.

`scan-released-sdk-filesystem.py` independently enumerates the installed tree
through descriptor-relative `scandir`, `stat`, `open` and reads. Before complete
producer enumeration it retains only the four fixed audio, LLVM, portable curl
and shared curl manifests, each nonempty and at most 1 MiB, through the same
descriptor identity fences.
The resulting `ProducerInventory` binds those private payloads to the enumerated
hash and size before archive checks; payloads are excluded from serialized maps.
Producer-tree zero-byte files remain valid. Notices, licenses and single-file
metadata reads remain nonempty. Unlike directory
tar generation, any unreadable entry fails the scan. It inventories the same
fixed roots and seven files, resolves and fences notice links, and implements
the shared `ProviderReader` interface for actual libcurl/libcares bytes. Provider
reads admit only versioned canonical regular paths under `/usr/local/lib`, require
UID 0 for the file and every ancestor including `/`, and fence UID/GID with the
other descriptor identities before and after reading. The scanner hashes the three
build tools and twelve LLVM roles, and checks final filesystem identities.
`ScannerImage` uses a separate task-owned container: UID/GID 65534, read-only
root and reviewed scanner/helper mounts, no network, dropped capabilities, no
privileges or credentials, fixed `/usr/bin/python3 -I -B` entrypoint and bounded
wait/log output. Host-side image, command, source, mount and ownership fences
surround execution and cleanup. Only this owned executed scanner may be stopped
on failure; the acquisition container remains unstarted.
The local log driver uses exactly one 128 MiB file with `compress=false`, and
that configuration is checked with the other container fences. Moby's
[local driver configuration](https://github.com/moby/moby/blob/docker-v29.4.2/daemon/logger/local/config.go)
rejects its default compression setting when `max-file=1`; explicit disabling
allows startup while preserving the log bound.

Its separate schema-2 `filesystem-qualification.json` receipt records
`image_code_executed` as `true`, `false` or `null`, along with the exact
index/platform/config/producer/consumer, scanner/helper hashes, run identity,
its own container and cleanup outcome. `true` requires an accepted Docker start
response or a complete owned-container fence with coherent running/exited state,
true-integer PID, nonzero valid UTC RFC3339Nano `StartedAt`, and false paused,
restarting and dead flags. This records Docker's execution boundary, not proof
of particular CPU instructions. Moby's [start implementation](https://github.com/moby/moby/blob/docker-v29.4.2/daemon/start.go)
starts the task before setting the running state; its
[state transitions](https://github.com/moby/moby/blob/docker-v29.4.2/daemon/container/state.go)
preserve `StartedAt` after exit, and its
[inspection](https://github.com/moby/moby/blob/docker-v29.4.2/daemon/inspect.go)
formats that timestamp as RFC3339Nano.

A start response can be lost after execution begins. Cleanup's complete fences
before mutation and after stop also reconcile this evidence; proven execution
survives later cleanup failure. `false` means no start was attempted and no
fenced started state was observed. After any attempted start, missing inspection,
fence drift, malformed state or only a created/zero-start snapshot leaves `null`
unless a prior accepted response or fenced observation proved `true`. A created
snapshot cannot exclude a pending start request, even when removal succeeds.
Only fixed booleans and null enter this evidence; raw state/timestamps are not
published. Acquisition receipts and scanner reports retain their separate
schema 1. Reconciliation never grants qualification: success still requires the
accepted start response, completed scan, full comparison and successful cleanup.
Success requires exact equality of all three maps, every metadata/tool field and
canonical digests. An omitted unrelated producer file, missing notice, changed
resolved path, malformed report, source drift or cleanup failure stops the final
collection. This is trusted-producer filesystem qualification; image Python and
OS remain trusted. It does not establish runtime, export, gameplay or audible
acceptance, and does not claim independence from a malicious image OS.

Failed filesystem qualification retains a fixed host phase and, after a valid
Docker wait response, an integer exit status in `0..255`. The collector fences
the exited container before reading logs even when the process failed. Nonzero
exit output is limited to 4 KiB and must use the same strict stdout-only Docker
framing as successful reports. The only retained scanner output is an exact
stopped-report schema containing a fixed stage and allowlisted failure code,
plus an allowlisted errno name for OS errors. Unknown codes, extra fields,
stderr, raw tracebacks, paths, exception strings and malformed output never
enter the receipt. A nonzero exit always fails qualification, including when
its output resembles a successful inventory. Diagnostics preserve owned
cleanup and every source, image, mount, isolation and inventory comparison gate;
they provide failure evidence rather than SDK acceptance.

The fixed `portable-final` row admits only `atrinik/classic-portable-build:1.22.0`
with this authenticated release identity:

| Field | Immutable value |
| --- | --- |
| Producer revision | `eb1f6af78216adb4375826cdb70ef78a61ab403a` |
| Classic consumer | `bd5317a03cdc82f029105c5dc26428b09fcd54b3` |
| OCI index | `sha256:74761e930f5d57face2d81efb0dc50dd4ce32ce1204810e56580bf68a5972ebc` |
| Linux/amd64 manifest | `sha256:5e30957e54277bdaadeeffa42246258dc9df2086f3fb41f2125d041735ac72aa` |
| OCI config | `sha256:c35dbeac2679d79dab524a13c9a3b74a8187878ecd3b3dff52bd2892418d7a79` |

Release publication and tested-image identity have been reviewed separately.
This row enables collection; it does not certify the final installed inventories
or filesystem equality. After source review, CI and merge, dispatch
`qualify-released-linux-sdk.yml` on reviewed `main` and inspect the actual
`released-linux-sdk-portable-final-<run>-<attempt>` artifact. Both its acquisition
and filesystem qualification receipts must pass on this exact tuple before
wrapper metadata/inventory pins are adopted. Later semantic releases do not
retarget this row. No CLI, environment or workflow input can supply image pins,
producer identities or paths. A missing final policy still fails closed, and no
historical target is relabeled. Export, runtime and user hardware qualification
remain separate.

The filesystem scanner adapts descriptor-relative enumeration and byte-recording
from the MIT-licensed wrapper at
[`a9661a2bd978107fe4e01e45b2e22fcd1e2d095c`](https://github.com/atrinik/atrinik/tree/a9661a2bd978107fe4e01e45b2e22fcd1e2d095c):
`atrinik_workspace/linux_export.py` (`_identity`, `_inventory`, `_open_root`,
`_open_beneath`) and `atrinik_workspace/linux_portable.py` (`byte_record`,
`verified_tree_inventory`). Copyright (c) 2026 Atrinik contributors; the MIT
permission and warranty notice are retained through this repository's `LICENSE`.
This reuses contemporaneously MIT-licensed infrastructure, not historical Classic
material or a historical relicensing grant. Adaptations add fixed roots, shared
budgets, independent notice resolution and a bounded machine-readable report.

Offline validation:

```sh
python3 -m unittest discover -s tools/tests -p 'test*released*sdk*.py' -v
```
