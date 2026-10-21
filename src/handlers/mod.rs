use std::collections::HashMap;
use std::sync::OnceLock;

use crate::error::{CryptoengError, Result};
use crate::request::CryptoengRequest;
use crate::storage::{RuntimeState, Storage};
use crate::types::method::MethodType;

mod native;
mod pms;

/// Handler function type - unified for all request types via trait object
pub type HandlerFn = fn(&dyn CryptoengRequest, &mut Storage, &mut RuntimeState) -> Result<Vec<u8>>;

/// Entry for registering a handler with the inventory system
pub struct HandlerEntry {
    pub method_type: MethodType,
    pub handler: HandlerFn,
}

inventory::collect!(HandlerEntry);

/// Global handler registry, built lazily on first access
static HANDLER_REGISTRY: OnceLock<HashMap<i32, HandlerFn>> = OnceLock::new();

fn get_registry() -> &'static HashMap<i32, HandlerFn> {
    HANDLER_REGISTRY.get_or_init(|| {
        let mut map = HashMap::new();
        for entry in inventory::iter::<HandlerEntry> {
            map.insert(entry.method_type.code(), entry.handler);
        }
        map
    })
}

pub fn dispatch(
    request: &dyn CryptoengRequest,
    storage: &mut Storage,
    runtime: &mut RuntimeState,
) -> Result<Vec<u8>> {
    let registry = get_registry();
    let method_type = request.method_type();
    let code = method_type.code();

    match registry.get(&code) {
        Some(handler) => handler(request, storage, runtime),
        None => Err(CryptoengError::UnknownMethod(method_type)),
    }
}

#[macro_export]
macro_rules! register_handler {
    ($method_type:expr, $handler:expr) => {
        inventory::submit! {
            $crate::handlers::HandlerEntry {
                method_type: $method_type,
                handler: $handler,
            }
        }
    };
}
