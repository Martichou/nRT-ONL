#[macro_use]
extern crate log;

use std::{
    io::Error,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use pnet::{
    datalink::{self, Channel::Ethernet, NetworkInterface},
    packet::ethernet::EthernetPacket,
};
use tokio::sync::mpsc::{self, Receiver, Sender};

mod frame;
mod icmp;
mod tcp;

#[derive(Debug, PartialEq)]
pub enum State {
    Error,
    Ukn,
    Down,
    Up,
}

#[derive(Debug, Default)]
pub(crate) struct SharedState {
    // last_xx_pkt is the Unix time in micros.
    // can be truncated to fit in Usize.
    last_rx_pkt: AtomicUsize,
    last_tx_pkt: AtomicUsize,
}

#[derive(Debug)]
pub struct Config {
    /// The MAX time difference in µs between RX/TX packets.
    /// Default to 1s (1000000µs).
    rxtx_threshold: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            rxtx_threshold: 1000000,
        }
    }
}

#[derive(Debug)]
pub struct Onl {
    ch: (Sender<State>, Receiver<State>),
    iface: NetworkInterface,
    config: Config,
}

impl Onl {
    pub fn new(iface_name: String, config: Option<Config>) -> Result<Self, Error> {
        // Find the network interface with the provided name
        let interface = datalink::interfaces()
            .into_iter()
            .find(|iface: &NetworkInterface| iface.name == iface_name);

        if interface.is_none() {
            return Err(Error::new(
                std::io::ErrorKind::NotFound,
                "iface not found, check name and permissions",
            ));
        }

        Ok(Self {
            ch: mpsc::channel(100),
            iface: interface.unwrap(),
            config: config.unwrap_or(Config::default()),
        })
    }

    /// Start the outage notification process.
    /// Returning the receiver of a MPSC channel.
    pub fn start(self) -> Result<Receiver<State>, Error> {
        // Create a datalink channel to receive packets on (will be SOCK_RAW and eth_p_all)
        let (_, mut rx) = match datalink::channel(&self.iface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => unreachable!("channel type not supported"),
            Err(e) => return Err(e),
        };

        // The task handling packets need write access
        // to the shared state. While the analysis only
        // need read access.
        let state: Arc<SharedState> = Arc::new(SharedState::default());

        // Clone the object we need in our task (those that needs to be).
        let cstate = state.clone();
        let cch_tx = self.ch.0.clone();
        // Task to launch analysis as per packets info
        tokio::spawn(async move {
            // Need some inner state to know if we're in an "outage" or not
            let mut current = State::Ukn;

            loop {
                let start_overall = std::time::Instant::now();

                let rx_pkt = cstate.last_rx_pkt.load(Ordering::Relaxed);
                let tx_pkt = cstate.last_tx_pkt.load(Ordering::Relaxed);
                let abs_diff = rx_pkt.abs_diff(tx_pkt);
                info!("Absdiff: {}µs", abs_diff);

                match current {
                    State::Up | State::Ukn => {
                        // If the diff is bigger than 1s
                        if abs_diff > self.config.rxtx_threshold {
                            debug!("Down here");
                            _ = cch_tx.send(State::Down).await;
                            current = State::Down;
                        }
                    }
                    State::Down => {
                        if abs_diff < self.config.rxtx_threshold {
                            debug!("Up here");
                            _ = cch_tx.send(State::Up).await;
                            current = State::Up;
                        }
                    }
                    _ => {}
                }

                // If the state is still Ukn, this means we're Up.
                if current == State::Ukn {
                    debug!("Was Ukn");
                    _ = cch_tx.send(State::Up).await;
                    current = State::Up;
                }

                let duration_overall = start_overall.elapsed();
                thread::sleep(Duration::from_secs(1) - duration_overall);
            }
        });

        // Task for the handling of packets
        tokio::spawn(async move {
            loop {
                match rx.next() {
                    Ok(packet) => {
                        frame::handle_ethernet_frame(
                            state.as_ref(),
                            &self.iface,
                            &EthernetPacket::new(packet).unwrap(),
                        );
                    }
                    Err(e) => {
                        error!("datalink::channel: unknown error: {}", e);
                        _ = self.ch.0.send(State::Error).await;
                    }
                }
            }
        });

        Ok(self.ch.1)
    }
}
