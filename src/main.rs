//! Cryptoeng service server implementation.

use oplus_cryptoeng_stub::{BnCryptoeng, CryptoengService};
use rsbinder::*;
use tracing::{info, Level};
use tracing_logcat::{LogcatMakeWriter, LogcatTag};
use tracing_subscriber::EnvFilter;

const DESCRIPTOR: &str = "vendor.oplus.hardware.cryptoeng.ICryptoeng/default";

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing with Android logcat
    // Filter out verbose rsbinder logs unless RUST_LOG is set
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("oplus_cryptoeng_stub=debug,rsbinder=warn"));

    let tag = LogcatTag::Fixed("cryptoeng".to_owned());
    let writer = LogcatMakeWriter::new(tag).expect("Failed to initialize logcat writer");

    tracing_subscriber::fmt()
        .with_writer(writer)
        .with_max_level(Level::TRACE)
        .with_env_filter(filter)
        .init();

    // Initialize the process state
    ProcessState::init_default();

    // Start the thread pool
    ProcessState::start_thread_pool();

    // Create and register the service
    let service = BnCryptoeng::new_binder(CryptoengService::new());
    hub::add_service(DESCRIPTOR, service.as_binder())?;

    info!(descriptor = DESCRIPTOR, "Cryptoeng service started");

    // Join the thread pool to handle requests
    let _ = ProcessState::join_thread_pool();

    Ok(())
}
