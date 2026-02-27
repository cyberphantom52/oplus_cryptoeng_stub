# oplus_cryptoeng_stub

A Rust implementation of the `ICryptoeng` AIDL interface (`vendor.oplus.hardware.cryptoeng`) for OxygenOS/ColorOS ports that cannot run the stock cryptoeng HAL. This restores functionality for features that depend on the cryptoeng service, such as **Privacy Password**, **App Lock**, **Hide Apps**, and **File/Photo Vault**.

> [!CAUTION]
> **This is NOT a secure implementation.** The stock HAL stores sensitive data inside a Trusted Execution Environment (TrustZone/TEE). This stub **cannot** do that — it stores everything in `/data/vendor_de/0/cryptoeng/` encrypted with AES-256-GCM using a key stored right next to the data (not derived from the hardware keystore). **Any password protection can be trivially bypassed by deleting the storage files.** Use this only to get the features working on unsupported ROMs; do not rely on it for actual security.


## Building

### Prerequisites

- Rust (edition 2024)
- [Android NDK](https://developer.android.com/ndk) (e.g. `android-ndk-r29`)
- [`cargo-ndk`](https://github.com/nickelc/cargo-ndk)

### Compile for Android

```bash
ANDROID_NDK_HOME=/path/to/android-ndk cargo ndk -P 35 -t arm64-v8a build --release
```

The output binary will be at:
```
target/aarch64-linux-android/release/vendor-oplus-hardware-cryptoeng-service
```

## License

This project is licensed under the [GPL-3.0](LICENSE).

This project is not affiliated with or endorsed by Oplus, OnePlus, or OPPO.
