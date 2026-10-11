# Windows producer

The producer uses checksum-pinned LLVM-MinGW 20261006, LLVM 23.1.3,
compiler-rt and UCRT. `dependencies.json` retains the dependency source versions,
hashes, patches, features and licenses from the pinned MXE recipes. Libraries
are rebuilt into `/opt/atrinik-windows` with the LLVM tools.

The Classic source qualifier is
[bbaf7785b6f7c5905b3f5c52f079d6198da0d540](https://github.com/atrinik/classic/tree/bbaf7785b6f7c5905b3f5c52f079d6198da0d540),
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

GLib's and Cairo's GNU TLS macros retain callback pointers but do not force the CRT TLS
registration directory into an LLVM/MinGW link. The target GLib and Cairo recipes require
`_tls_used`; the host recipe and library features remain unchanged. `pe_tls.py`
checks the actual PE TLS directory and callback array against each library's retained
symbols. It binds the native probe to that exact DLL's callback and process
attach flag. The producer's native bundle verifies the DLL hash, observes the
callback flag, exercises a real GPrivate destructor using the configured POSIX
thread backend, and explicitly unloads the DLL. Missing registration is also
fatal through GLib's existing critical diagnostic.

For focused diagnosis, run `qualify-glib-tls.py --work-dir ABSENT_DIRECTORY
--output ABSENT_DIRECTORY` inside the pinned LLVM SDK, with an optional
`--source-archive` that must match the locked GLib hash. It rebuilds GLib with
and without the mandatory TLS reference, preserves linker-map evidence and
import/export comparison, and stages the original SDK DLL as another negative
control. Run the resulting `run-glib-tls-qualification.ps1` on native Windows;
all three lanes must meet their declared outcomes. This focused test does not
replace complete candidate SDK, consumer, font, media, or GPU qualification.

The same focused helper accepts `--library cairo` (GLib is the default) with
Cairo's locked source archive and distinct work/output directories. Its native
probe observes `_cairo_mutex_initialized == 2` immediately after loading,
before any API can initialize the mutexes lazily, exercises image/context and
Win32 font APIs, releases the objects, unloads and reloads the DLL. The original
and relinked controls must fail on missing TLS registration. Successful unload
is recorded without claiming direct observation of the detach callback's work.
