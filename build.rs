use std::path::PathBuf;

fn main() {
    rsbinder_aidl::Builder::new()
        .source(PathBuf::from(
            "aidl/vendor/oplus/hardware/cryptoeng/ICryptoeng.aidl",
        ))
        .version(1)
        .hash("765136eb397eb5b85ee1e089d8fec72c15e266b3")
        .set_async_support(false)
        .output(PathBuf::from("cryptoeng.rs"))
        .generate()
        .expect("Failed to generate AIDL bindings");

    let mut keystore = rsbinder_aidl::Builder::new()
        .include_dir("aidl")
        .set_async_support(false)
        .output("keystore2.rs");
    for directory in [
        "aidl/android/hardware/security/keymint",
        "aidl/android/system/keystore2",
    ] {
        let mut sources: Vec<_> = std::fs::read_dir(directory)
            .expect("read canonical Android AIDL directory")
            .map(|entry| entry.expect("read Android AIDL entry").path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "aidl")
            })
            .collect();
        sources.sort();
        for source in sources {
            keystore = keystore.source(source);
        }
    }
    keystore
        .generate()
        .expect("Failed to generate Keystore2 client bindings");

    // Re-run build script if AIDL files change
    println!("cargo:rerun-if-changed=aidl/");
}
