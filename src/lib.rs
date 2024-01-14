#[macro_use]
extern crate log;

use std::io::Error;

use pnet::{
    datalink::{self, Channel::Ethernet, NetworkInterface},
    packet::ethernet::EthernetPacket,
};
use tokio::sync::mpsc::{self, Receiver, Sender};

pub mod icmp;
pub mod tcp;

mod frame;

#[derive(Debug)]
pub struct Onl {
    ch: (Sender<String>, Receiver<String>),
    iface: NetworkInterface,
}

impl Onl {
    pub fn new(iface_name: String) -> Result<Self, Error> {
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
        })
    }

    /// Start the outage notification process.
    /// Returning the receiver of a MPSC channel.
    pub fn start(self) -> Result<Receiver<String>, Error> {
        // Create a datalink channel to receive packets on (will be SOCK_RAW and eth_p_all)
        let (_, mut rx) = match datalink::channel(&self.iface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => unreachable!("channel type not supported"),
            Err(e) => return Err(e),
        };

        // Task to launch analysis as per packets info
        tokio::spawn(async move {});

        // Task for the handling of packets
        tokio::spawn(async move {
            loop {
                match rx.next() {
                    Ok(packet) => {
                        frame::handle_ethernet_frame(
                            &self.iface,
                            &EthernetPacket::new(packet).unwrap(),
                        );
                    }
                    Err(e) => {
                        error!("datalink::channel: unknown error: {}", e);
                        _ = self.ch.0.send("Error: ukn".to_owned()).await;
                    }
                }
            }
        });

        Ok(self.ch.1)
    }
}
