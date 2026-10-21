use oplus_cryptoeng_stub::{BnCryptoeng, CryptoengService};
use rsbinder::*;
use tracing::{Level, info};
use tracing_logcat::{LogcatMakeWriter, LogcatTag};
use tracing_subscriber::EnvFilter;

const DESCRIPTOR: &str = "vendor.oplus.hardware.cryptoeng.ICryptoeng/default";

fn init_logging() {
    #[cfg(not(debug_assertions))]
    let filter = EnvFilter::new("none");
    #[cfg(debug_assertions)]
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("oplus_cryptoeng_stub=debug,rsbinder=warn"));

    let tag = LogcatTag::Fixed(env!("CARGO_PKG_NAME").to_owned());
    let writer = LogcatMakeWriter::new(tag).expect("Failed to initialize logcat writer");

    tracing_subscriber::fmt()
        .with_writer(writer)
        .with_max_level(Level::TRACE)
        .with_env_filter(filter)
        .init();
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    init_logging();

    // Initialize the process state
    ProcessState::init_default()?;

    // Start the thread pool
    ProcessState::start_thread_pool();

    // Create and register the service
    let service = BnCryptoeng::new_binder(CryptoengService::new());
    hub::add_service(DESCRIPTOR, service.as_binder())?;

    info!(descriptor = DESCRIPTOR, "Cryptoeng service started");

    ProcessState::join_thread_pool()?;
    Ok(())
}
