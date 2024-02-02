#[macro_use]
extern crate log;

use n_rt_onl::{Config, Onl};
use std::{env, process};

#[tokio::main]

async fn main() -> Result<(), anyhow::Error> {
    // Define log level
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "INFO")
    }

    // Init logger/tracing
    tracing_subscriber::fmt::init();

    let iface_name = match env::args().nth(1) {
        Some(n) => n,
        None => {
            println!("USAGE: onl <NETWORK INTERFACE>");
            process::exit(1);
        }
    };

    let onl = Onl::new(
        iface_name,
        Some(Config {
			ebpf_prog_path: String::from("/home/martichou/Works/n-rt-onl-ebpf/target/bpfel-unknown-none/release/n-rt-onl-ebpf"),
            icmp_targets: Some(vec![String::from("1.1.1.1")]),
            icmp_interval: Some(1000),
            ..Default::default()
        }),
    )?;
    let mut receiver = onl.start()?;

    while let Some(e) = receiver.recv().await {
        info!("Got an event: {:?}", e);
    }

    Ok(())
}
