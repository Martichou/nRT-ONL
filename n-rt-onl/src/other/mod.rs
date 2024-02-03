use std::time::{SystemTime, UNIX_EPOCH};

mod frame;
mod imple;

pub(crate) fn get_now_truncated() -> usize {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros();

    now_unix as usize
}
