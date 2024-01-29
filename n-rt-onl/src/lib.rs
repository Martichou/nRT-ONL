#[macro_use]
extern crate log;

use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, maps::HashMap, Bpf};
use aya_log::BpfLogger;
use fastping_rs::Pinger;
use pnet::datalink::{self, NetworkInterface};
use std::io::Error;
use std::time::Duration;
use tokio::sync::mpsc::{self, Receiver, Sender};

#[cfg(debug_assertions)]
static BPF_BYTES: &[u8] =
    include_bytes_aligned!("../../target/bpfel-unknown-none/debug/n-rt-onl-ebpf");
#[cfg(not(debug_assertions))]
static BPF_BYTES: &[u8] =
    include_bytes_aligned!("../../target/bpfel-unknown-none/release/n-rt-onl-ebpf");

#[derive(Debug, PartialEq)]
pub enum State {
    Error,
    Ukn,
    Down,
    Up,
}

#[derive(Debug, Clone)]
pub struct Config {
    /// The MAX time difference in ns between RX/TX packets.
    /// Default to 1.5s (1500000000ns).
    pub rxtx_threshold: u64,

    /// Determine if the library will send ICMP to specified
    /// servers as a sanity check for pkts reception. If your
    /// server/machine is already handling a lots of packets,
    /// this may not be necessary. Otherwise, it is recommended
    /// to avoid false positive
    pub icmp_targets: Option<Vec<String>>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            rxtx_threshold: 1500000000,
            icmp_targets: None,
        }
    }
}

#[derive(Debug)]
pub struct Onl {
    event_rx: Receiver<State>,
    event_tx: Sender<State>,
    iface_name: String,
    config: Config,
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

        Ok(Self {
            event_tx: channel.0,
            event_rx: channel.1,
            iface_name: ifname,
            config: config.unwrap_or_default(),
            bpf: Bpf::load(BPF_BYTES).unwrap(),
        })
    }

    /// Start the outage notification process.
    /// Returning the receiver of a MPSC channel.
    pub fn start(mut self) -> Result<Receiver<State>, anyhow::Error> {
        if let Err(e) = BpfLogger::init(&mut self.bpf) {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {}", e);
        }

        let program: &mut Xdp = self.bpf.program_mut("n_rt_onl_ebpf").unwrap().try_into()?;
        program.load()?;
        program.attach(&self.iface_name, XdpFlags::default())
			.context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

        // If some targets for icmp are specified, run the pinger
        // Note: we don't care about the result, the eBPF prog will take care
        // of that part.
        if let Some(targets) = self.config.icmp_targets {
            tokio::spawn(async move {
                let (pinger, results) = match Pinger::new(Some(1000), Some(32)) {
                    Ok((pinger, results)) => (pinger, results),
                    Err(e) => panic!("Error creating pinger: {}", e),
                };

                for t in targets {
                    pinger.add_ipaddr(&t);
                }

                pinger.run_pinger();

                while results.recv().is_ok() {}
            });
        }

        tokio::spawn(async move {
            let bpf_map = self.bpf.map_mut("PKT_TIMESTAMP").unwrap();
            let pkt_timestamp = HashMap::<_, u8, u64>::try_from(bpf_map).unwrap();

            // Need some inner state to know if we're in an "outage" or not
            let mut current = State::Ukn;

            loop {
                let start_overall = std::time::Instant::now();

                let rx_pkt = pkt_timestamp.get(&0, 0).unwrap_or_default();
                let tx_pkt = pkt_timestamp.get(&1, 0).unwrap_or_default();
                let abs_diff = rx_pkt.abs_diff(tx_pkt);

                debug!(
                    "Running check: Abs[{}] vs Threshold[{})]",
                    abs_diff, self.config.rxtx_threshold
                );
                match current {
                    State::Up | State::Ukn => {
                        // If the diff is bigger than 1s
                        if abs_diff > self.config.rxtx_threshold {
                            info!("State now DOWN");
                            _ = self.event_tx.send(State::Down).await;
                            current = State::Down;
                        }
                    }
                    State::Down => {
                        if abs_diff < self.config.rxtx_threshold {
                            info!("State now UP");
                            _ = self.event_tx.send(State::Up).await;
                            current = State::Up;
                        }
                    }
                    _ => {}
                }

                // If the state is still Ukn, this means we're Up.
                if current == State::Ukn {
                    _ = self.event_tx.send(State::Up).await;
                    current = State::Up;
                }

                let duration_overall = start_overall.elapsed();
                std::thread::sleep(Duration::from_secs(1) - duration_overall);
            }
        });

        Ok(self.event_rx)
    }
}
