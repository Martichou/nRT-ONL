#[macro_use]
extern crate log;

#[cfg(all(target_os = "linux", not(feature = "userspace")))]
use aya::Bpf;
use pnet::datalink::{self, NetworkInterface};
use serde::{Deserialize, Serialize};
use std::io::Error;
use tokio::sync::mpsc::{self, Receiver, Sender};

mod common;
#[cfg(all(target_os = "linux", not(feature = "userspace")))]
mod ebpf;
#[cfg(any(feature = "userspace", not(target_os = "linux")))]
mod other;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum State {
    Error,
    Ukn,
    Down,
    Up,
}

impl From<usize> for State {
    fn from(val: usize) -> Self {
        match val {
            0 => State::Error,
            1 => State::Ukn,
            2 => State::Down,
            3 => State::Up,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    #[cfg(all(target_os = "linux", not(feature = "userspace")))]
    /// Path to the ebpf program.
    pub ebpf_prog_path: String,
    /// The MAX time difference in ms between RX/TX packets.
    /// Default to 1500ms (1500000000ns).
    pub rxtx_threshold: usize,

    /// Determine if the library will send ICMP to specified
    /// servers as a sanity check for pkts reception. If your
    /// server/machine is already handling a lots of packets,
    /// this may not be necessary. Otherwise, it is recommended
    /// to avoid false positive
    pub icmp_targets: Option<Vec<String>>,
    pub icmp_interval: Option<u64>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            #[cfg(all(debug_assertions, target_os = "linux", not(feature = "userspace")))]
            ebpf_prog_path: String::from("./target/bpfel-unknown-none/debug/n-rt-onl-ebpf"),
            #[cfg(all(not(debug_assertions), target_os = "linux", not(feature = "userspace")))]
            ebpf_prog_path: String::from("./target/bpfel-unknown-none/release/n-rt-onl-ebpf"),
            rxtx_threshold: 1500,
            icmp_targets: None,
            icmp_interval: None,
        }
    }
}

#[derive(Debug)]
pub struct Onl {
    event_rx: Receiver<State>,
    event_tx: Sender<State>,
    iface_name: String,
    config: Config,
    #[cfg(all(target_os = "linux", not(feature = "userspace")))]
    bpf: Bpf,
}

impl Onl {
    pub fn new(ifname: String, config: Option<Config>) -> Result<Self, anyhow::Error> {
        // Find the network interface with the provided name
        let interface = datalink::interfaces()
            .into_iter()
            .find(|iface: &NetworkInterface| iface.name == ifname);

        if interface.is_none() {
            return Err(Error::new(
                std::io::ErrorKind::NotFound,
                format!("iface({}) not found, check name and permissions", ifname),
            )
            .into());
        }

        let channel = mpsc::channel(100);
        let config = config.unwrap_or_default();
        #[cfg(all(target_os = "linux", not(feature = "userspace")))]
        let bpf_path = config.ebpf_prog_path.clone();

        Ok(Self {
            event_tx: channel.0,
            event_rx: channel.1,
            iface_name: ifname,
            config,
            #[cfg(all(target_os = "linux", not(feature = "userspace")))]
            bpf: Bpf::load_file(bpf_path).unwrap(),
        })
    }
}
