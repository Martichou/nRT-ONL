use std::sync::atomic::AtomicUsize;

use crate::utils::get_now_truncated;

#[derive(Debug)]
pub(crate) struct SharedData {
    // last_xx_pkt is the Unix time in micros.
    // can be truncated to fit in Usize.
    pub last_rx_pkt: AtomicUsize,
    pub last_tx_pkt: AtomicUsize,
}

impl Default for SharedData {
    fn default() -> Self {
        SharedData {
            last_rx_pkt: get_now_truncated().into(),
            last_tx_pkt: get_now_truncated().into(),
        }
    }
}
