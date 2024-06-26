use aya::maps::HashMap;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya_log::BpfLogger;
use std::time::Duration;
use tokio::sync::mpsc::Receiver;

use crate::{common, Onl, State};

impl Onl {
    /// Start the outage notification process.
    /// Returning the receiver of a MPSC channel.
    pub fn start(mut self) -> Result<Receiver<State>, anyhow::Error> {
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

        if let Err(e) = BpfLogger::init(&mut self.bpf) {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {}", e);
        }

        // error adding clsact to the interface if it is already added is harmless
        // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
        let _ = tc::qdisc_add_clsact(&self.iface_name);
        let program_egress: &mut SchedClassifier = self
            .bpf
            .program_mut("n_rt_onl_ebpf_egress")
            .unwrap()
            .try_into()?;
        program_egress.load()?;
        program_egress.attach(&self.iface_name, TcAttachType::Egress)?;

        let program_ingress: &mut SchedClassifier = self
            .bpf
            .program_mut("n_rt_onl_ebpf_ingress")
            .unwrap()
            .try_into()?;
        program_ingress.load()?;
        program_ingress.attach(&self.iface_name, TcAttachType::Ingress)?;

        // If some targets for icmp are specified, run the pinger
        // Note: we don't care about the result, the eBPF prog will take care
        // of that part.
        if let Some(targets) = self.config.icmp_targets {
            common::start_pinger(targets, self.config.icmp_interval);
        }

        tokio::spawn(async move {
            let bpf_map = self.bpf.map_mut("PKT_TIMESTAMP").unwrap();
            let pkt_timestamp = HashMap::<_, u8, u64>::try_from(bpf_map).unwrap();

            // Need some inner state to know if we're in an "outage" or not
            let mut current = State::Ukn;
            _ = self.event_tx.send(State::Ukn).await;

            // Delay the start of the analysis by rxtx_threshold.
            // At first we don't have any stats, so no need to check anything
            tokio::time::sleep(Duration::from_millis(self.config.rxtx_threshold as u64)).await;

            loop {
                let start_overall = std::time::Instant::now();

                let rx_pkt = pkt_timestamp.get(&0, 0).unwrap_or_default();
                let tx_pkt = pkt_timestamp.get(&1, 0).unwrap_or_default();
                let abs_diff = rx_pkt.abs_diff(tx_pkt);

                match current {
                    State::Up | State::Ukn => {
                        // If the diff is bigger than rxtx_threshold (converted to ns)
                        if abs_diff > (self.config.rxtx_threshold * 10000000) as u64 {
                            info!("State now DOWN");
                            _ = self.event_tx.send(State::Down).await;
                            current = State::Down;
                        }
                    }
                    State::Down => {
                        if abs_diff < (self.config.rxtx_threshold * 10000000) as u64 {
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
                // Perform three times more analysis than the rxtx_threshold.
                // This is to avoid bad race condition where it would take
                // more time than needed to detect outages.
                tokio::time::sleep(
                    Duration::from_millis(self.config.rxtx_threshold.div_ceil(3) as u64)
                        - duration_overall,
                )
                .await;
            }
        });

        Ok(self.event_rx)
    }
}
