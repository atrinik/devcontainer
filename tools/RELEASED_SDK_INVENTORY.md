# Released portable SDK inventory foundation

`released_sdk_inventory.py` is an internal acquisition helper for the existing
collector's authenticated, task-owned `StoppedImage` and archive protocol. It
has no CLI, credentials, registry operations, release pins or image execution.
The collector imports it through an explicit same-checkout path under isolated
Python. Only its internal final-target path invokes inventory and execution;
`FINAL_TARGETS` is empty until actual release coordinates are reviewed. The three
fixed 1.18.0 targets and their producer mapping remain authoritative.

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
checks the consumer in both contract and shader record, retains all twelve LLVM
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
fixed roots and seven files, resolves and fences notice links, hashes the three
build tools and twelve LLVM roles, and checks final filesystem identities.
`ScannerImage` uses a separate task-owned container: UID/GID 65534, read-only
root and reviewed scanner/helper mounts, no network, dropped capabilities, no
privileges or credentials, fixed `/usr/bin/python3 -I -B` entrypoint and bounded
wait/log output. Host-side image, command, source, mount and ownership fences
surround execution and cleanup. Only this owned executed scanner may be stopped
on failure; the acquisition container remains unstarted.

Its separate `filesystem-qualification.json` receipt explicitly records
`image_code_executed: true`, the exact index/platform/config/producer/consumer,
scanner/helper hashes, run identity, its own container and cleanup outcome.
Success requires exact equality of all three maps, every metadata/tool field and
canonical digests. An omitted unrelated producer file, missing notice, changed
resolved path, malformed report, source drift or cleanup failure stops the final
collection. This is trusted-producer filesystem qualification; image Python and
OS remain trusted. It does not establish runtime, export, gameplay or audible
acceptance, and does not claim independence from a malicious image OS.

The remaining admission step requires actual merged producer P and released D:
add the real fixed package/tag/index tuple to `TARGETS`, and the corresponding
`producer_revision`, `consumer_commit`, `manifest_digest` and `config_digest`
record to `FINAL_TARGETS`; then add that exact name to the trusted workflow
matrix. A target added without its policy fails closed. No CLI, environment or
workflow input can supply image pins, producer identities or paths. Do not
invent those coordinates or relabel any historical target. The final code and
mapping need independent review and actual hosted qualification before adopting
wrapper metadata/inventory pins. Workflow tests cover the generic dormant path;
there is no final released-image evidence yet.

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
