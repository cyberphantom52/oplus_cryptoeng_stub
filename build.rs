use std::path::PathBuf;

fn main() {
    // Generate Rust bindings from AIDL files
    rsbinder_aidl::Builder::new()
        .output(PathBuf::from("cryptoeng.rs"))
        .generate()
        .expect("Failed to generate AIDL bindings");

    // Re-run build script if AIDL files change
    println!("cargo:rerun-if-changed=aidl/");
}
