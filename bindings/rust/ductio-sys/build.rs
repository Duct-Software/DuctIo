use std::{
    env,
    hash::{Hash, Hasher},
    path::PathBuf,
    process::Command,
};

fn run(cmd: &mut Command) {
    let status = cmd.status().expect("failed to launch native build tool");
    assert!(status.success(), "native build failed: {cmd:?}");
}

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let source = manifest.join("../../..").canonicalize().unwrap();
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let mut compiler_key = std::collections::hash_map::DefaultHasher::new();
    env::var_os("CC").hash(&mut compiler_key);
    env::var_os("CXX").hash(&mut compiler_key);
    env::var_os("AR").hash(&mut compiler_key);
    env::var_os("RANLIB").hash(&mut compiler_key);
    env::var_os("TARGET").hash(&mut compiler_key);
    env::var_os("DUCTIO_EVENTS_MODEL").hash(&mut compiler_key);
    let build = out.join(format!("cmake-{:016x}", compiler_key.finish()));
    let target = env::var("CARGO_CFG_TARGET_OS").unwrap();
    assert!(
        target == "linux" || target == "macos",
        "the Rust SDK supports Linux and macOS; no {target} backend is validated here"
    );
    let noise = true;
    let tls = env::var_os("CARGO_FEATURE_TLS_OPENSSL").is_some();

    // An explicit prebuilt directory is useful to validate an installed CMake
    // consumer. The default uses the exact source tree containing this crate.
    let prebuilt = env::var_os("DUCTIO_SYS_LIB_DIR").map(PathBuf::from);
    let libdir = if let Some(path) = prebuilt.clone() {
        path
    } else {
        let mut configure = Command::new("cmake");
        configure
            .arg("-S")
            .arg(&source)
            .arg("-B")
            .arg(&build)
            .arg("-DCMAKE_BUILD_TYPE=Release")
            .arg(format!(
                "-DDUCT_WITH_NOISE={}",
                if noise { "ON" } else { "OFF" }
            ))
            .arg(format!(
                "-DDUCT_WITH_OPENSSL={}",
                if tls { "ON" } else { "OFF" }
            ))
            .arg("-DDUCT_BUILD_TESTS=OFF")
            .arg("-DDUCT_BUILD_EXAMPLES=OFF");
        if let Some(model) = env::var_os("DUCTIO_EVENTS_MODEL") {
            configure.arg(format!("-DDUCT_EVENTS_MODEL={}", model.to_string_lossy()));
        } else if target == "macos" {
            configure.arg("-DDUCT_EVENTS_MODEL=kqueue");
        }
        if target == "macos" {
            // Mach-O archives require Apple tools; PATH may contain GNU binutils.
            let ar = env::var_os("AR").unwrap_or_else(|| "/usr/bin/ar".into());
            let ranlib = env::var_os("RANLIB").unwrap_or_else(|| "/usr/bin/ranlib".into());
            configure.arg(format!("-DCMAKE_AR={}", ar.to_string_lossy()));
            configure.arg(format!("-DCMAKE_RANLIB={}", ranlib.to_string_lossy()));
        }
        run(&mut configure);
        run(Command::new("cmake")
            .arg("--build")
            .arg(&build)
            .arg("--target")
            .arg("ductio")
            .arg("--parallel")
            .arg("2"));
        build.clone()
    };
    let include = if prebuilt.is_some() {
        PathBuf::from(
            env::var_os("DUCTIO_SYS_INCLUDE_DIR")
                .expect("DUCTIO_SYS_INCLUDE_DIR is required with DUCTIO_SYS_LIB_DIR"),
        )
    } else {
        source.join("include")
    };
    let generated = if prebuilt.is_some() {
        env::var_os("DUCTIO_SYS_GENERATED_INCLUDE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| include.clone())
    } else {
        build.join("include")
    };
    assert!(
        include.join("duct_noise.h").exists(),
        "installed DuctIo must have DUCT_WITH_NOISE=ON"
    );
    println!("cargo:rustc-link-search=native={}", libdir.display());
    if target == "macos" {
        let openssl_libdir = env::var_os("OPENSSL_LIB_DIR")
            .map(PathBuf::from)
            .or_else(|| {
                let output = Command::new("pkg-config")
                    .args(["--variable=libdir", "openssl"])
                    .output()
                    .ok()?;
                output
                    .status
                    .success()
                    .then(|| PathBuf::from(String::from_utf8_lossy(&output.stdout).trim()))
            });
        if let Some(path) = openssl_libdir {
            println!("cargo:rustc-link-search=native={}", path.display());
        }
    }
    println!("cargo:rustc-link-lib=static=ductio");
    if noise {
        println!("cargo:rustc-link-lib=ssl");
        println!("cargo:rustc-link-lib=crypto");
    }
    println!("cargo:rustc-link-lib=pthread");
    println!("cargo:rustc-link-lib=m");

    let mut shim = cc::Build::new();
    if target == "macos" {
        shim.archiver(env::var_os("AR").unwrap_or_else(|| "/usr/bin/ar".into()));
    }
    shim.file(manifest.join("shim.c"))
        .include(&include)
        .include(&generated)
        .define("_GNU_SOURCE", None)
        .flag_if_supported("-std=c2x")
        .compile("ductio_rs_shim");

    let mut builder = bindgen::Builder::default()
        .header(manifest.join("wrapper.h").to_string_lossy())
        .clang_arg(format!("-I{}", include.display()))
        .clang_arg(format!("-I{}", generated.display()))
        .clang_arg("-std=c2x")
        .clang_arg("-D_GNU_SOURCE")
        .allowlist_type("duct_.*")
        .allowlist_function("duct_.*")
        .allowlist_function("ductio_rs_.*")
        .allowlist_var("duct_.*")
        .allowlist_var("rc_.*")
        .allowlist_var("x_.*")
        .allowlist_var("seal_.*")
        .allowlist_var("listener_.*")
        .derive_default(true)
        .generate_comments(true);
    // Bindgen can otherwise discover a different clang on PATH (e.g. 18
    // headers with libclang 19). Use the native compiler's resource headers.
    if let Ok(resource) = Command::new(shim.get_compiler().path())
        .arg("-print-resource-dir")
        .output()
    {
        if resource.status.success() {
            let path = String::from_utf8_lossy(&resource.stdout);
            builder = builder.clang_arg(format!("-resource-dir={}", path.trim()));
        }
    }
    let bindings = builder
        .generate()
        .expect("bindgen failed on public DuctIo headers; install libclang 19+");
    bindings.write_to_file(out.join("bindings.rs")).unwrap();
    println!(
        "cargo:rerun-if-changed={}",
        libdir.join("libductio.a").display()
    );
    println!("cargo:rerun-if-changed={}", include.display());
    if prebuilt.is_none() {
        for native_sources in ["src", "os", "cmake", "CMakeLists.txt"] {
            println!(
                "cargo:rerun-if-changed={}",
                source.join(native_sources).display()
            );
        }
    }
    println!(
        "cargo:rerun-if-changed={}",
        generated.join("duct_build_config.h").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        manifest.join("wrapper.h").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        manifest.join("shim.c").display()
    );
    println!("cargo:rerun-if-env-changed=DUCTIO_SYS_GENERATED_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=DUCTIO_SYS_LIB_DIR");
    println!("cargo:rerun-if-env-changed=DUCTIO_SYS_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=CXX");
    println!("cargo:rerun-if-env-changed=AR");
    println!("cargo:rerun-if-env-changed=RANLIB");
    println!("cargo:rerun-if-env-changed=LIBCLANG_PATH");
    println!("cargo:rerun-if-env-changed=CLANG_PATH");
    println!("cargo:rerun-if-env-changed=DUCTIO_EVENTS_MODEL");
    println!("cargo:rerun-if-env-changed=OPENSSL_LIB_DIR");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_TLS_OPENSSL");
}
