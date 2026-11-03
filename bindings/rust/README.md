# DuctIo Rust SDK (v0.1.1)

This workspace is part of the DuctIo source distribution. `ductio-sys`
generates raw FFI from the **public** C headers; `ductio` provides a safe
Linux and macOS API for the engine, protocols, TCP and UDP listeners and dials,
Noise-sealed wires, inter legs, descriptor attachment, timers, custom wire
codecs, session commands, and runtime counters. Optional OpenSSL TLS server
support is available through a feature. The crates do
not depend on any application built on top of DuctIo.

## Build

Requires Rust 1.85+, CMake 3.21+, a C23-capable compiler and libclang 19+,
OpenSSL development headers/libraries, and a Linux or macOS host. The default
`cargo test --workspace` configures the containing DuctIo source tree with
`DUCT_WITH_NOISE=ON`, builds a static `ductio`, and generates bindings from
that tree's public headers. No source is downloaded by `build.rs`.

On macOS, use Clang 19+ (for example Homebrew LLVM), set `LIBCLANG_PATH` to
its library directory, and make the OpenSSL library discoverable through
`pkg-config` or `OPENSSL_LIB_DIR`. Export `MACOSX_DEPLOYMENT_TARGET=14.4` or
later: the C library's floor, which rustc does not take on its own. Run loopback tests with
`cargo test --workspace -- --test-threads=1` because engine tests share one
process-global native runtime.

Enable `tls-openssl` on `ductio` to build DuctIo's OpenSSL TLS adapter and
expose `TlsWire`. A prebuilt archive used with this feature must have
`DUCT_WITH_OPENSSL=ON`. The adapter is server-side; clients can use any TLS
library.

For an installed CMake package, set **both** `DUCTIO_SYS_LIB_DIR` (directory
containing `libductio.a`) and `DUCTIO_SYS_INCLUDE_DIR` (the package's installed
`include`, including `duct_build_config.h`). This path still requires a
Noise-enabled build. The bindings use those installed headers rather than the
source tree's headers. Keep library and headers from the same build. The ABI
test compares Rust layout with a C shim compiled against the selected headers;
it cannot prove that an independently supplied library was built from those
same headers.

`cmake --install` places this workspace at `<prefix>/share/ductio/rust`.
From there, build with `DUCTIO_SYS_LIB_DIR=<prefix>/lib` and
`DUCTIO_SYS_INCLUDE_DIR=<prefix>/include` (adjust the library directory for
the platform's CMake install layout). The installed workspace does not need
the DuctIo C source tree.

The repository also contains `installed-consumer/`: configure it with
`cmake -S installed-consumer -B /tmp/ductio-consumer -DCMAKE_PREFIX_PATH=<install-prefix>`
and build/run `ductio_installed_smoke` to exercise the exported
`DuctIo::ductio` target and its OpenSSL dependency resolution.

## Ownership and callbacks

| Object | Lifetime and thread |
|---|---|
| `Engine` | One per process. Owner-thread only, `!Send + !Sync`. `stop` joins workers, destroys the runtime, then releases protocols and pending command contexts. |
| `Listener` | Holds the native sockets reported by `duct_listener_bind`. It can be revoked with `Engine::close_listener`; dropping only the handle does not stop listening. A native close timeout is reported and its fd is forgotten to prevent revoking an unrelated future socket with the same number. |
| `Protocol` | Moved into `Engine`; C borrows its config, name, handler context and wire until engine destruction. |
| `NoiseKeypair` | Generates or derives a local X25519 public key without exposing raw FFI; its private bytes are wiped on drop. `into_wire` transfers a copy to an owned `NoiseWire`. |
| `NoiseWire` | Owns a boxed Noise config and public wire; both survive every connection. The SDK uses `zeroize` to wipe its local key copies and owned config on release. Responder Noise authentication rejects peers before message 2 unless `verify_with`, an owned allow-list, or a per-peer PSK provider explicitly permits them; `Handler::peer_key` is an additional default-deny gate. |
| `TlsWire` | Owns an OpenSSL server context and sealed wire. The supplied context controls certificate, key and client verification policy. Available with `tls-openssl`. |
| `CustomWire` | Implemented by a thread-safe Rust codec with fixed header width and replay-safe parsing. The adapter checks frame bounds and copies packed bytes into native staging. |
| `InterIngress` | Cloneable ingress handle that serializes native inter-lane calls and is revoked before engine destruction. `InterHost` runs on a dedicated host thread and receives owned output packets. |
| `FdAttachRequest` | An `OwnedFd` moves into an asynchronous attach request. Once its callback runs, C owns the descriptor even if attachment fails. Dropping the request does not cancel it. |
| `SessionToken` | Copyable generation-checked C handle plus Rust engine id. It does not own a C session. |
| Callback frame/identity | Borrowed by C for the callback. The safe handler sees a slice valid only within that invocation; it cannot be saved without copying. |
| `Engine::post` payload | Heap-owned. A command not yet run is reclaimed on terminal session close; once run, its buffer remains owned until C calls the response release callback or the engine is destroyed. For sealed sessions, posting rejects a token until `Handler::peer_key` accepts it. Return success means posted, not remote acknowledgement. |

Every Rust `Handler` callback is caught with `catch_unwind`; a panic in a
response-producing callback closes that session. Handlers run on DuctIo
workers and should hand off work without blocking. Do not call synchronous C
invokes from callbacks. The safe API intentionally omits
`duct_session_invoke_sync`: its timeout does **not** cancel the posted callback.
The `ductio-sys` API remains unsafe and exposes the full public C surface.

`dial_tcp` and `dial_udp` only initiate a connection and return a `DialId`. The session token
arrives in `Handler::open` and is correlated with that dial in
`Handler::dial_open`; pre-session failures call `Handler::dial_error` with the
same id. An open callback occurs before Noise peer authentication. The SDK
gates RX frames and `post` until `peer_key` accepts, including a first frame
carried in the same PDU as peer authentication. Applications must still
perform any identity or authorization exchange required by their own protocol.
`Handler::authenticated` fires after the SDK gate opens, so a host
thread can safely use the token at that notification.
If a handler panics, the SDK requests an asynchronous session close; posts
already accepted by the worker are not retroactively cancelled.

`Protocol::plain` uses a length-prefixed stream wire; `Protocol::datagram`
uses a packet-preserving datagram wire. `Protocol::sealed` accepts a `NoiseWire`
configured for stream or datagram framing. `NoiseKeypair::generate` creates a
new local identity, and `NoiseKeypair::from_private` derives its public key
from an existing 32-byte secret. Bind with `bind_tcp` or `bind_udp`
and dial with `dial_tcp` or `dial_udp` accordingly. `Engine::stats` returns
`None` when the native library has compiled out counters. A successful post
is an enqueue, not a peer acknowledgement.

`Engine::attach_inter` opens an application-controlled inter leg. `InterHost`
collects emitted packets; `InterIngress::packet` or `batch` delivers them to a
matching leg. `Engine::post_to` selects a connection and reports native
pack/enqueue completion through `Handler::send_done`. Host transport and
delivery guarantees remain application concerns.

`Engine::attach_stream_fd` and `attach_packet_fd` transfer a Unix descriptor
to a session; `FdAttachRequest::wait` reports the native attach result.
`Engine::schedule_timer` and `cancel_timer` address timers by per-session tag;
`Handler::timer` receives ticks on the worker. `Protocol::custom` accepts a
`CustomWire` codec. Connection join/loss callbacks are available on `Handler`.

Raw bindings cover the public C entries enabled by the native build. Advanced
C protocol hooks and custom sealed engines remain available through
`ductio-sys` under the application's own safety review. The SDK accepts Linux
and macOS. On macOS, the C library defaults to kqueue; select
`DUCT_EVENTS_MODEL=poll` in CMake to test the portable reactor. The macOS
native kqueue and poll C suites, Rust loopback/bulk tests and ABI checks are
covered together. The bulk regressions exercise the shared backpressure fixes
described in [issue #40](https://github.com/Duct-Software/DuctIo/issues/40);
general protocol-owned reply cycles remain outside this integration. Windows has a
native MinGW backend, but the Rust facade still requires Windows socket
ownership bindings and a Windows build/test run.

## Apple backend and API additions

`NoiseWire` uses the compact datagram engine for UDP. Builders own the hello,
mask key, allowed peer keys, per-peer PSK callback, opening callback and join-lead
cover key through native teardown. Callbacks can run concurrently; panic means
refusal (PSK/verification) or the end of the opening. PSK callback results use
per-worker-thread storage that C copies immediately and Rust wipes on replacement
and thread exit. Both peers must agree on hello width, wire/cover keys, framing
variant and `DUCT_HANDSHAKE_MASK`; old unmasked peers do not interoperate by default.

`Protocol::with_timeouts` sets idle/handshake bounds. `dial_tcp_via` and
`dial_udp_via` take an interface index. `Handler::frame_with_info` supplies leg,
flags and payload counters before the current frame is accepted; those counters
are not delivery acknowledgements. `schedule_engine_timer` invokes
`Handler::engine_timer` with no session. `request_stop`, `stop_on_signals`,
`wait_for_stop` and pool readings retain the owner-thread facade's cleanup rules.
OS randomness, constant-time equality and HMAC-SHA256 are available as safe helpers.

The common CTest `rust_sdk` test reuses its CMake build's library and generated
headers, so a green Cargo run cannot silently exercise another reactor or config.
`DUCTIO_SYS_GENERATED_INCLUDE_DIR` selects generated headers when consuming an
uninstalled archive. For standalone Cargo builds, `DUCTIO_EVENTS_MODEL` selects
kqueue/poll or epoll/poll. The safe facade remains native Linux/macOS in this integration;
iOS backend smoke validation is C, and iOS crypto integration needs its own OpenSSL.
