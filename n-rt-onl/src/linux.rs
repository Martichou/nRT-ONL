use aya::maps::HashMap;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya_log::BpfLogger;
use fastping_rs::Pinger;
use std::time::Duration;
use tokio::sync::mpsc::Receiver;

use crate::{Onl, State};

impl Onl {
    /// Start the outage notification process.
    /// Returning the receiver of a MPSC channel.
    pub fn start(mut self) -> Result<Receiver<State>, anyhow::Error> {
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
            tokio::spawn(async move {
                let (pinger, results) = match Pinger::new(self.config.icmp_interval, Some(32)) {
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
