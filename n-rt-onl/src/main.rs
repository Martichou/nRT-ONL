#[macro_use]
extern crate log;

use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, maps::HashMap, Bpf};
use aya_log::BpfLogger;
use clap::Parser;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[derive(Debug, PartialEq)]
pub enum State {
    Error,
    Ukn,
    Down,
    Up,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    // Define log level
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "DEBUG");
    }

    // Init logger/tracing
    tracing_subscriber::fmt::init();

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

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/n-rt-onl-ebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/n-rt-onl-ebpf"
    ))?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let program: &mut Xdp = bpf.program_mut("n_rt_onl_ebpf").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let pkt_timestamp: HashMap<_, u8, u64> =
        HashMap::try_from(bpf.map_mut("PKT_TIMESTAMP").unwrap())?;

    let mut current = State::Ukn;
    loop {
        let start_overall = std::time::Instant::now();

        let rx_pkt = pkt_timestamp.get(&0, 0).unwrap_or_default();
        let tx_pkt = pkt_timestamp.get(&1, 0).unwrap_or_default();
        let abs_diff = rx_pkt.abs_diff(tx_pkt);

        debug!("Running check: {} <= {} - {}", abs_diff, rx_pkt, tx_pkt);
        match current {
            State::Up | State::Ukn => {
                // If the diff is bigger than 1s
                if abs_diff > 1000000 {
                    info!("State now UP");
                    // _ = cch_tx.send(State::Down).await;
                    current = State::Down;
                }
            }
            State::Down => {
                if abs_diff < 1000000 {
                    info!("State now DOWN");
                    // _ = cch_tx.send(State::Up).await;
                    current = State::Up;
                }
            }
            _ => {}
        }

        // If the state is still Ukn, this means we're Up.
        if current == State::Ukn {
            // _ = cch_tx.send(State::Up).await;
            current = State::Up;
        }

        let duration_overall = start_overall.elapsed();
        std::thread::sleep(std::time::Duration::from_secs(1) - duration_overall);
    }
}
