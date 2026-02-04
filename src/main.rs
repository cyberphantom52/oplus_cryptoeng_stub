//! Cryptoeng service server implementation.

use oplus_cryptoeng_stub::{BnCryptoeng, CryptoengService, DebugCryptoengService};
use rsbinder::*;
use std::env;
use tracing::{info, warn};
use tracing_subscriber::prelude::*;

const DESCRIPTOR: &str = "vendor.oplus.hardware.cryptoeng.ICryptoeng/default";

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing with Android logcat
    tracing_subscriber::registry()
        .with(tracing_android::layer("cryptoeng")?)
        .init();
    
    let args: Vec<String> = env::args().collect();
    let debug_mode = args.iter().any(|a| a == "--debug");

    // Initialize the process state
    ProcessState::init_default();

    // Start the thread pool
    ProcessState::start_thread_pool();

    // Create and register the service
    if debug_mode {
        warn!("DEBUG MODE ENABLED - all binder transactions will be logged");

        // Use debug service that logs all transactions
        let service = Binder::new(DebugCryptoengService::new());
        hub::add_service(DESCRIPTOR, service.as_binder())?;
    } else {
        // Use normal service (generated from AIDL)
        let service = BnCryptoeng::new_binder(CryptoengService::new());
        hub::add_service(DESCRIPTOR, service.as_binder())?;
    }

    info!(descriptor = DESCRIPTOR, "service started");

    // Join the thread pool to handle requests
    let _ = ProcessState::join_thread_pool();

    Ok(())
}

