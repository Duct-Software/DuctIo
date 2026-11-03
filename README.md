# DuctIo

A high-performance C23 runtime for protocol-driven networking. Applications implement protocol logic through declarative callbacks—reading frames, assembling responses, and declaring state transitions—while the runtime manages reactors, zero-copy wire framing, scheduling, and delivery.

## Architecture

The engine enforces a strict architectural boundary between I/O and execution:

* **I/O Reactor Threads:** Own OS event loops (`epoll`, `kqueue`, `IOCP`, `WSAPoll`), network sockets, connection lifecycles, and lock-free ring buffers (Ordered Lock-free Buffers, or OLB).
* **Worker Threads:** Execute application callbacks (`on_frame`, `on_dgram`, coroutine handlers) without direct socket access. Responses are staged into connection ring buffers or parked under transient backpressure without blocking reactors.
* **Lock-free Queueing:** A Weighted Fair Queue (WFQ) schedules incoming work to workers across priority lanes without mutex contention.
* **Declarative Control:** Callbacks return a `duct_response_t` containing outbound payloads and a `control` block that commands runtime actions: timer adjustments, stream state changes, leg binding, read throttling, or session termination.

## Example: TCP Echo Server

```c
#include <duct.h>
#include <stdint.h>

static duct_result_t
on_frame(duct_session_t *s, duct_conn_id_t conn_id,
         const duct_frame_t *frame, duct_response_t *out, void *proto_state)
{
    (void)s;
    (void)conn_id;
    (void)proto_state;

    /* Echo incoming payload back to the sender */
    duct_response_echo(out, frame);
    return rc_ok;
}

int main(void)
{
    duct_engine_cfg_t cfg = {
        .io_threads = 1u,
        .workers    = 2u,
    };
    duct_engine_t *engine = duct_engine_launch(&cfg);
    if (!engine)
        return 1;

    duct_proto_t *proto = duct_proto_create_tcp("echo", on_frame);
    if (!proto) {
        duct_engine_destroy(engine);
        return 1;
    }

    uint16_t port = 9000u;
    if (duct_io_listen(engine, "0.0.0.0", &port, proto) != rc_ok) {
        duct_proto_destroy(proto);
        duct_engine_destroy(engine);
        return 1;
    }

    /* Blocks until shutdown is signaled */
    duct_engine_wait(engine);

    duct_proto_destroy(proto);
    duct_engine_destroy(engine);
    return 0;
}
```

## Features

* **Pluggable Wire Layer:** Decouples protocol payloads from transport framing. Built-in stream codecs include raw framing and length-prefixed framing.
* **Sealed Wire Cryptography:** Zero-trust architecture where I/O threads identify record boundaries without decrypting data. Decryption and cryptographic state transitions happen worker-side.
  * **TLS 1.3:** Built-in OpenSSL adapter (`duct_tls_openssl_vtbl`).
  * **Noise Protocol Framework:** Native `Noise_IKpsk2` and `Noise_XKpsk3` engines (`duct_noise_vtbl`, `duct_noise_vtbl_dgram`).
* **Multi-Transport & Multi-Leg Sessions:** A single session can manage multiple concurrent network legs (primary, fallback, roaming), multiplexed streams, datagram associations, and device attachments (`duct_conn_attach_device`).
* **Cooperative Concurrency:** Multiplexed streams can execute as stackless async tasks or stackful coroutines on worker threads.
* **In-Flight Protocol Switching:** `duct_proto_switch` provides a two-phase barrier to upgrade connections on the fly (e.g., plaintext negotiation upgrading to sealed cryptography).
* **Multi-Platform Reactors:**
  * **Linux:** `epoll` (default) or `poll`.
  * **macOS / iOS:** `kqueue` (default) or `poll`.
  * **Windows:** `WSAPoll` (default), `IOCP`, or `WSAEventSelect` (via MSYS2 MinGW-w64 or Clang64).
* **Rust Bindings:** Official FFI (`ductio-sys`) and idiomatic Rust interface (`ductio`) available in [`bindings/rust`](bindings/rust/README.md).

## Prerequisites

* **Compiler:** C23 compiler with `constexpr` support (GCC 13+ or Clang 19+).
* **Build System:** CMake 3.21+ and Ninja.
* **Dependencies:**
  * **Linux:** `pthread` (system).
  * **macOS:** `libsystem` (system, macOS 14.4+ / iOS 17.4+ deployment target for `os_sync`).
  * **Windows:** MSYS2 environment (MINGW64 or CLANG64; MSVC is not supported).
  * **Optional:** OpenSSL 3.x for TLS 1.3 or Noise engines.

### Package Installation

```sh
# Ubuntu / Debian
sudo apt install build-essential cmake ninja-build libssl-dev

# macOS (Homebrew)
brew install cmake ninja openssl@3

# Windows (MSYS2 CLANG64)
pacman -S mingw-w64-clang-x86_64-clang mingw-w64-clang-x86_64-cmake \
          mingw-w64-clang-x86_64-ninja mingw-w64-clang-x86_64-openssl
```

## Building

DuctIo uses CMake Presets for reproducible configuration:

```sh
# Development build (Debug, no LTO)
cmake --preset dev
cmake --build --preset dev

# Development build with OpenSSL TLS and Noise support
cmake --preset dev-openssl
cmake --preset dev-noise

# Release build with Link-Time Optimization (LTO)
cmake --preset ci
cmake --build --preset ci
```

### Configuration Options

Options can be customized via `-D<OPTION>=<VALUE>`:

| Option | Default | Description |
|---|---|---|
| `DUCT_BUILD_TESTS` | `ON` (top-level) | Build unit and integration tests |
| `DUCT_BUILD_EXAMPLES` | `ON` (top-level) | Build runnable example programs |
| `DUCT_BUILD_RUST_TESTS`| `OFF` (`ON` with Noise on native Linux/macOS) | Build and run Rust binding tests |
| `DUCT_WITH_OPENSSL` | `OFF` | Enable OpenSSL TLS 1.3 engine |
| `DUCT_WITH_NOISE` | `OFF` | Enable Noise Protocol Framework engine |
| `DUCT_EVENTS_MODEL` | Platform default | Event reactor backend (`epoll`, `kqueue`, `iocp`, `poll`, `wsaevent`) |
| `DUCT_ENABLE_RUNTIME_STATS` | `OFF` | Compile internal performance and diagnostic counters |

### Integration in CMake Projects

```cmake
# Subdirectory integration
add_subdirectory(ductio)
target_link_libraries(your_target PRIVATE DuctIo::ductio)

# Or via installed package
find_package(DuctIo CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE DuctIo::ductio)
```

## Testing

```sh
# Run the complete test suite
ctest --test-dir build/<preset-dir> --output-on-failure

# Run a specific test
ctest --test-dir build/<preset-dir> -R echo_test --output-on-failure
```

The test suite covers connection lifecycle, stress under descriptor and memory limits, multi-leg migration, sealed wire handshakes, and transport state machines.

## Project Structure

```
include/          Public C23 API headers (installed)
src/              Core runtime implementation
src/include/      Internal engine headers (WFQ, OLB, session table, codecs)
os/               Platform reactor implementations (Linux, macOS, Windows)
arch/             ISA-specific context switching routines
bindings/rust/    Rust crate (ductio) and raw FFI bindings (ductio-sys)
examples/         Runnable example services
test/             Unit and integration tests
```

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE) for details.

## Contact

[info@duct.software](mailto:info@duct.software)
