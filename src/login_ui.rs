//! Line-delimited JSON for authenticated local frontends. Never emits input values.
use serde_json::{json, Value};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

static ENABLED: AtomicBool = AtomicBool::new(false);
pub fn enable(value: bool) {
    ENABLED.store(value, Ordering::Relaxed);
}
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}
pub fn emit(value: Value) {
    if enabled() {
        println!("{}", value);
        let _ = std::io::stdout().flush();
    }
}
pub fn error(message: &str) {
    emit(json!({"event": "error", "message": message}));
}
