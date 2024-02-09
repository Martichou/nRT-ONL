use std::{
    io::Error,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use once_cell::sync::Lazy;
use pnet::{
    datalink::{self, Channel::Ethernet, NetworkInterface},
    packet::ethernet::EthernetPacket,
};
use tokio::sync::mpsc::Receiver;

use crate::{
    common,
    other::{frame, get_now_truncated},
    Onl, State,
};

pub(crate) static GLOBAL_STATE: Lazy<SharedData> = Lazy::new(SharedData::default);

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

impl Onl {
    /// Start the outage notification process.
    /// Returning the receiver of a MPSC channel.
    pub fn start(self) -> Result<Receiver<State>, anyhow::Error> {
        // Find the network interface with the provided name
        let interface = match datalink::interfaces()
            .into_iter()
            .find(|iface: &NetworkInterface| iface.name == self.iface_name)
        {
            Some(itf) => itf,
            None => {
                return Err(Error::new(
                    std::io::ErrorKind::NotFound,
                    "iface not found, check name and permissions",
                )
                .into())
            }
        };

        let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => unreachable!("channel type not supported"),
            Err(e) => return Err(e.into()),
        };

        // If some targets for icmp are specified, run the pinger
        // Note: we don't care about the result, the eBPF prog will take care
        // of that part.
        if let Some(targets) = self.config.icmp_targets {
            common::start_pinger(targets, self.config.icmp_interval);
        }

        // Clone the object we need in our task (those that needs to be).
        let cch_tx = self.event_tx.clone();
        // Task to launch analysis as per packets info
        tokio::spawn(async move {
            // Need some inner state to know if we're in an "outage" or not
            let mut current = State::Ukn;

            loop {
                let start_overall = std::time::Instant::now();

                let rx_pkt = GLOBAL_STATE.last_rx_pkt.load(Ordering::SeqCst);
                let tx_pkt = GLOBAL_STATE.last_tx_pkt.load(Ordering::SeqCst);
                let abs_diff = rx_pkt.abs_diff(tx_pkt);

                match current {
                    State::Up | State::Ukn => {
                        // If the diff is bigger than rxtx_threshold
                        if abs_diff > self.config.rxtx_threshold * 1000 {
                            info!("State now DOWN");
                            _ = cch_tx.send(State::Down).await;
                            current = State::Down;
                        }
                    }
                    State::Down => {
                        if abs_diff < self.config.rxtx_threshold * 1000 {
                            info!("State now UP");
                            _ = cch_tx.send(State::Up).await;
                            current = State::Up;
                        }
                    }
                    _ => {}
                }

                // If the state is still Ukn, this means we're Up.
                if current == State::Ukn {
                    _ = cch_tx.send(State::Up).await;
                    current = State::Up;
                }

                let duration_overall = start_overall.elapsed();
                // Perform three times more analysis than the rxtx_threshold.
                // This is to avoid bad race condition where it would take
                // more time than needed to detect outages.
                std::thread::sleep(
                    Duration::from_millis(self.config.rxtx_threshold.div_ceil(3) as u64)
                        - duration_overall,
                );
            }
        });

        // Task for the handling of packets
        tokio::spawn(async move {
            loop {
                match rx.next() {
                    Ok(packet) => {
                        frame::handle_ethernet_frame(
                            &interface,
                            &EthernetPacket::new(packet).unwrap(),
                        );
                    }
                    Err(e) => {
                        error!("datalink::channel: unknown error: {}", e);
                        _ = self.event_tx.send(State::Error).await;
                    }
                }
            }
        });

        Ok(self.event_rx)
    }
}
