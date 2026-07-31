use std::sync::{Condvar, Mutex, OnceLock};

static FATAL_STATE: OnceLock<FatalState> = OnceLock::new();

struct FatalState {
    reason: Mutex<Option<String>>,
    cv: Condvar,
}

pub(crate) fn fatal_reason() -> Option<String> {
    let state = fatal_state();
    match state.reason.lock() {
        Ok(guard) => guard.clone(),
        Err(_) => Some("runtime fatal reason mutex poisoned".to_string()),
    }
}

pub(crate) fn wait_fatal_reason() -> String {
    let state = fatal_state();
    let mut guard = match state.reason.lock() {
        Ok(guard) => guard,
        Err(_) => return "runtime fatal reason mutex poisoned".to_string(),
    };
    loop {
        if let Some(reason) = guard.as_ref() {
            return reason.clone();
        }
        guard = match state.cv.wait(guard) {
            Ok(guard) => guard,
            Err(_) => return "runtime fatal reason condvar wait poisoned".to_string(),
        };
    }
}

pub(crate) fn record_fatal(reason: impl Into<String>) {
    let state = fatal_state();
    if let Ok(mut guard) = state.reason.lock()
        && guard.is_none()
    {
        *guard = Some(reason.into());
        state.cv.notify_all();
    }
}

pub(crate) fn clear_fatal_reason() {
    let state = fatal_state();
    if let Ok(mut guard) = state.reason.lock() {
        *guard = None;
    }
}

fn fatal_state() -> &'static FatalState {
    FATAL_STATE.get_or_init(|| FatalState {
        reason: Mutex::new(None),
        cv: Condvar::new(),
    })
}
