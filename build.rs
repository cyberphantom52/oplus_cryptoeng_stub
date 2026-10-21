use std::path::PathBuf;

fn main() {
    // Generate Rust bindings from AIDL files
    rsbinder_aidl::Builder::new()
        .source(PathBuf::from(
            "aidl/vendor/oplus/hardware/cryptoeng/ICryptoeng.aidl",
        ))
        .version(1)
        .hash("765136eb397eb5b85ee1e089d8fec72c15e266b3")
        .output(PathBuf::from("cryptoeng.rs"))
        .generate()
        .expect("Failed to generate AIDL bindings");

    // Re-run build script if AIDL files change
    println!("cargo:rerun-if-changed=aidl/");
}
