#[macro_use]
extern crate log;

#[cfg(target_os = "linux")]
use aya::Bpf;
use pnet::datalink::{self, NetworkInterface};
use std::io::Error;
use tokio::sync::mpsc::{self, Receiver, Sender};

mod common;
#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "linux")]
mod linux;

#[derive(Debug, PartialEq)]
pub enum State {
    Error,
    Ukn,
    Down,
    Up,
}

#[derive(Debug, Clone)]
pub struct Config {
    #[cfg(target_os = "linux")]
    /// Path to the ebpf program.
    pub ebpf_prog_path: String,
    /// The MAX time difference in ns between RX/TX packets.
    /// Default to 1.5s (1500000000ns).
    pub rxtx_threshold: u64,

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
            #[cfg(all(debug_assertions, target_os = "linux"))]
            ebpf_prog_path: String::from("../../target/bpfel-unknown-none/debug/n-rt-onl-ebpf"),
            #[cfg(all(not(debug_assertions), target_os = "linux"))]
            ebpf_prog_path: String::from("../../target/bpfel-unknown-none/release/n-rt-onl-ebpf"),
            rxtx_threshold: 1500000000,
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
    #[cfg(target_os = "linux")]
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

        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg based accounting, see https://lwn.net/Articles/837122/
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            debug!("remove limit on locked memory failed, ret is: {}", ret);
        }

        let channel = mpsc::channel(100);
        let config = config.unwrap_or_default();
        let bpf_path = config.ebpf_prog_path.clone();

        Ok(Self {
            event_tx: channel.0,
            event_rx: channel.1,
            iface_name: ifname,
            config,
            #[cfg(target_os = "linux")]
            bpf: Bpf::load_file(bpf_path).unwrap(),
        })
    }
}
