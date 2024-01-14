#[macro_use]
extern crate log;

use std::{env, process};

use n_rt_onl::Onl;

#[tokio::main]

async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Define log level
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "DEBUG")
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

    let onl = Onl::new(iface_name, None)?;
    let mut receiver = onl.start()?;

    while let Some(e) = receiver.recv().await {
        info!("Got an event: {:?}", e);
    }

    Ok(())
}