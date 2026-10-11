# Windows producer

The producer uses checksum-pinned LLVM-MinGW 20261006, LLVM 23.1.3,
compiler-rt and UCRT. `dependencies.json` retains the dependency source versions,
hashes, patches, features and licenses from the pinned MXE recipes. Libraries
are rebuilt into `/opt/atrinik-windows` with the LLVM tools.

The Classic source qualifier is
[3a1211f9557f3ebac112a51005fc94f3f9ba4495](https://github.com/atrinik/classic/tree/3a1211f9557f3ebac112a51005fc94f3f9ba4495),
published for review in [Classic PR 588](https://github.com/atrinik/classic/pull/588).
`classic-check-toolchain.json` pins that source for the neutral CMake interface,
recursive DLL and Python staging, and native test bundle.

The `windows-shared` stage builds the full dependency closure and records DLL
ownership, imports and hashed notices. The `classic-check` target supplies
client and library test dependencies. The default `windows` target additionally
supplies the external CPython SDK/runtime and native worldmaker dependencies.

Cross compilation and import inspection establish producer and package
contracts. Native Windows test execution, shipped-font equivalence, audible
playback and GPU qualification require separate evidence before release
acceptance. A private recovered LLVM cohort can diagnose dependency builds;
canonical publication still requires the production Dockerfile and CI.
