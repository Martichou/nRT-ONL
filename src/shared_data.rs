use std::sync::{atomic::AtomicUsize, Mutex};

use crate::utils::{get_now_truncated, AckStore};

#[derive(Debug)]
pub(crate) struct SharedData {
    // last_xx_pkt is the Unix time in micros.
    // can be truncated to fit in Usize.
    pub last_rx_pkt: AtomicUsize,
    pub last_tx_pkt: AtomicUsize,

    pub ack_store: Mutex<AckStore>,
}

impl Default for SharedData {
    fn default() -> Self {
        SharedData {
            last_rx_pkt: get_now_truncated().into(),
            last_tx_pkt: get_now_truncated().into(),
            ack_store: Mutex::new(AckStore::new()),
        }
    }
}
