# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Duct Software
"""Build and run native backend contracts in an available iOS simulator."""
import json
import pathlib
import subprocess
import sys

def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)

build = pathlib.Path(sys.argv[1]).resolve()
devices = json.loads(subprocess.check_output(["xcrun", "simctl", "list", "devices", "available", "-j"]))
choices = [d for runtime, ds in devices["devices"].items() if ".iOS-" in runtime for d in ds if d["isAvailable"]]
if not choices:
    raise SystemExit("No iOS simulator runtime is installed")
device = next((d for d in choices if d["state"] == "Booted"), choices[-1])
identifier = device["udid"]
booted_here = device["state"] != "Booted"
if booted_here:
    run("xcrun", "simctl", "boot", identifier)
try:
    run("xcrun", "simctl", "bootstatus", identifier, "-b", timeout=180)
    # Homebrew LLVM supplies C23, Xcode supplies iOS compiler-rt availability
    # helpers. The installed static archive itself needs no extra runtime path.
    resource = subprocess.check_output(["xcrun", "clang", "-print-resource-dir"], text=True).strip()
    run("cmake", "-S", str(pathlib.Path(__file__).resolve().parent.parent), "-B", str(build),
        "-DDUCT_BUILD_TESTS=ON", "-DDUCT_BUILD_RUST_TESTS=OFF",
        "-DCMAKE_EXE_LINKER_FLAGS=-resource-dir=" + resource)
    tests = ["core_futex", "events_contract", "darwin_xport", "crypto", "coro"]
    run("cmake", "--build", str(build), "--parallel", "4", "--target", *["ductio_" + n + "_test" for n in tests])
    for name in tests:
        executable = "ductio_" + name + "_test"
        path = build / "test" / (executable + ".app") / executable
        run("xcrun", "simctl", "spawn", identifier, str(path), timeout=60)
finally:
    if booted_here:
        run("xcrun", "simctl", "shutdown", identifier)
