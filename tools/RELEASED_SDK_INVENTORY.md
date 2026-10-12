# Released portable SDK inventory foundation

`released_sdk_inventory.py` is an internal acquisition helper for the existing
collector's authenticated, task-owned `StoppedImage` and archive protocol. It
has no CLI, credentials, registry operations, release pins or image execution.
It is not yet imported or invoked by `collect-released-sdk-metadata.py`; the
three fixed 1.18.0 targets and their producer mapping remain authoritative.

The helper streams `/opt/atrinik-portable` without extraction. It retains only
the fixed `audio-toolchain.json` and `llvm-toolchain.json` payloads, each nonempty
and at most 1 MiB, as private validation inputs on `ProducerInventory`. Before
parsing either manifest, it binds the retained bytes to the streamed record's
SHA-256 and size. These payloads are excluded from serialized inventory maps and
their digests; copying the records to a plain dictionary loses the payloads and
fails closed when a contract references a manifest. All other file payloads are
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
Debian notices, common licenses and build-tool executables must be nonempty;
only producer-tree inventory records may describe legitimate zero-byte files.

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

Final wiring requires actual merged Classic consumer/shader commit M, final
producer P and released image D. A subsequent reviewed change must add fixed
index, linux/amd64 manifest and config digests plus per-target producer revision;
validate M/P and shader metadata against those fixed constants; bind each saved
metadata file to the producer inventory; emit all three complete maps and their
canonical digests; and invoke the helper inside the collector's existing
cleanup-protected acquisition. Do not add caller-supplied pins, paths or trust
extensions. Original broad/classic/preliminary identities must remain unchanged.
Wrong final M/D fixtures and actual hosted unstarted-image collection remain
required at that integration point. Cleanup failure must still invalidate the
receipt. Even successful acquisition retains `installed-identity-only`,
`image_code_executed: false` and `final_portable_cohort: false`; it does not prove
runtime, export, gameplay or audible behavior.

Offline validation:

```sh
python3 -m unittest discover -s tools/tests -p 'test*released*sdk*.py' -v
```
