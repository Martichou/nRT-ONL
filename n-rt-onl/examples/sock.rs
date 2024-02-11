#[macro_use]
extern crate log;

use n_rt_onl::{Config, Onl, State};
use std::sync::atomic::Ordering;
use std::{
    env,
    io::Write,
    os::unix::net::UnixListener,
    process,
    sync::{atomic::AtomicUsize, Arc},
};
use tokio::sync::broadcast;

#[tokio::main]

async fn main() -> Result<(), anyhow::Error> {
    // Define log level
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "INFO")
    }

    // Init logger/tracing
    tracing_subscriber::fmt::init();

    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!(
            "USAGE ({}): sock <NETWORK INTERFACE> <PATH TO SOCKET>",
            args.len()
        );
        process::exit(1);
    }

    let iface_name = args[1].to_owned();
    let onl = Onl::new(
        iface_name,
        Some(Config {
            icmp_targets: Some(vec![String::from("1.1.1.1")]),
            icmp_interval: Some(1000),
            ..Default::default()
        }),
    )?;

    let prev_state = Arc::new(AtomicUsize::new(State::Ukn as usize));
    let prev_state2 = prev_state.clone();

    let (tx, mut _rx) = broadcast::channel(10);

    // Spawn the ONL event receiver in a task.
    tokio::spawn(async move {
        let mut receiver = onl.start().unwrap();
        debug!("Now listening to receiver");

        while let Some(e) = receiver.recv().await {
            info!("Got an event: {:?}", e);

            // Store current value in case new client connect
            prev_state.store(e.clone() as usize, Ordering::Relaxed);
            if let Err(e) = tx.send(e) {
                error!("Cannot send broadcast state: {}", e);
                break;
            }
        }
    });

    let sock_path = args[2].to_owned();
    let listener = UnixListener::bind(sock_path).unwrap();

    loop {
        let (mut socket, _remote_addr) = listener.accept().unwrap();
        let mut rx = _rx.resubscribe();
        let cps = prev_state2.clone();

        tokio::spawn(async move {
            debug!("New client!");
            // Should send previously received event
            let serialized =
                serde_json::to_string(&State::from(cps.load(Ordering::Relaxed))).unwrap();
            socket.write_all(serialized.as_bytes()).unwrap();

            // Wait for new event on the broadcast channel
            loop {
                match rx.recv().await {
                    Ok(e) => {
                        let serialized = serde_json::to_string(&e).unwrap();
                        socket.write_all(serialized.as_bytes()).unwrap();
                    }
                    Err(e) => {
                        error!("Cannot receive from the broadcast: {}", e);
                        break;
                    }
                }
            }
        });
    }
}
