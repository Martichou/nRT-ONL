use std::sync::atomic::Ordering;

use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use pnet::util::MacAddr;

use super::{get_now_truncated, imple::GLOBAL_STATE};

const SUPPORTED_SENT_PROTO: [IpNextHeaderProtocol; 4] = [
    IpNextHeaderProtocols::Udp,
    IpNextHeaderProtocols::Icmp,
    IpNextHeaderProtocols::Icmpv6,
    IpNextHeaderProtocols::Tcp,
];

#[derive(Debug, PartialEq)]
pub enum PacketDirection {
    Sending,
    Receiving,
    Unknown,
}

fn get_direction(source_mac: &MacAddr, interface: &NetworkInterface) -> PacketDirection {
    let mac = interface.mac;
    if let Some(rmac) = mac {
        if source_mac == &rmac {
            return PacketDirection::Sending;
        } else {
            return PacketDirection::Receiving;
        }
    }

    PacketDirection::Unknown
}

pub(crate) fn handle_ipv4_packet(
    source_mac: &MacAddr,
    interface: &NetworkInterface,
    ethernet: &EthernetPacket,
) {
    let interface_name = &interface.name;
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        let direction = get_direction(source_mac, interface);
        let is_sending = direction == PacketDirection::Sending;

        let ip4_src = header.get_source();
        let ip4_dst = header.get_destination();

        // Don't handle pkt if src is private when we're receiving the pkt or if both are private
        if (ip4_src.is_private() && !is_sending) || (ip4_src.is_private() && ip4_dst.is_private()) {
            trace!("Skipping: private to private");
            return;
        }

        // Don't handle broadcast
        if ip4_src.is_broadcast() || ip4_dst.is_broadcast() {
            trace!("Skipping: broadcast");
            return;
        }

        let protocol = header.get_next_level_protocol();
        if !SUPPORTED_SENT_PROTO.contains(&protocol) {
            debug!("Unsupported protocol: {}", protocol);
        }

        let now_truncated = get_now_truncated();
        if is_sending && SUPPORTED_SENT_PROTO.contains(&protocol) {
            GLOBAL_STATE
                .last_tx_pkt
                .store(now_truncated, Ordering::SeqCst);
        } else if !is_sending {
            // For each incoming packet, we suppose the network is "sane" so "reset" last_tx_pkt.
            GLOBAL_STATE
                .last_tx_pkt
                .store(now_truncated, Ordering::SeqCst);
            GLOBAL_STATE
                .last_rx_pkt
                .store(now_truncated, Ordering::SeqCst);
        }

        trace!(
            "{} -- {} - Packet: {:?} > {:?}",
            now_truncated,
            protocol,
            ip4_src,
            ip4_dst,
        );
    } else {
        error!("[{}]: Malformed IPv4 Packet", interface_name);
    }
}

pub(crate) fn handle_ethernet_frame(interface: &NetworkInterface, ethernet: &EthernetPacket) {
    let source_mac = ethernet.get_source();

    #[allow(clippy::single_match)]
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(&source_mac, interface, ethernet),
        _ => {}
    }
}
