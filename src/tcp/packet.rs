use std::net::IpAddr;

use bitflags::bitflags;
use pnet::packet::tcp::TcpPacket;

use crate::{frame::PacketDirection, GLOBAL_STATE};

trait TcpFlagExt {
    fn get_rflags(&self) -> TcpFlag;
}

bitflags! {
    #[derive(Debug)]
    struct TcpFlag: u8 {
        const FIN = 0x01;
        const SYN = 0x02;
        const RST = 0x04;
        const PSH = 0x08;
        const ACK = 0x10;
        const URG = 0x20;
        const ECE = 0x40;
        const CWR = 0x80;
    }
}

impl<'a> TcpFlagExt for TcpPacket<'a> {
    #[inline]
    fn get_rflags(&self) -> TcpFlag {
        TcpFlag::from_bits_truncate(self.get_flags())
    }
}

pub fn handle_tcp_packet(
    direction: PacketDirection,
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        let flags = tcp.get_rflags();
        if flags.contains(TcpFlag::ACK) {
            if direction == PacketDirection::Sending {
                let mut lgbl = GLOBAL_STATE.ack_store.lock().unwrap();
                lgbl.add_ack(tcp.get_sequence());
            } else if direction == PacketDirection::Receiving {
                let mut lgbl = GLOBAL_STATE.ack_store.lock().unwrap();
                lgbl.remove_ack(tcp.get_sequence());
            }
        }

        trace!(
            "[{}]: TCP Packet({:?} : {}): {}:{} > {}:{}; length: {}",
            interface_name,
            tcp.get_rflags(),
            tcp.get_sequence(),
            source,
            tcp.get_source(),
            destination,
            tcp.get_destination(),
            packet.len()
        );
    }
}
