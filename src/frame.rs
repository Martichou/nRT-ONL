use std::sync::atomic::Ordering;

use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use pnet::util::MacAddr;

use crate::utils::{get_now_truncated, Ipv6Ext};
use crate::{frame, GLOBAL_STATE};

const ALLOWED_PROTOCOL: [IpNextHeaderProtocol; 4] = [
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

fn update_state_rxtx(direction: &PacketDirection) {
    if direction == &PacketDirection::Unknown {
        return;
    }

    let now_truncated: usize = get_now_truncated();
    match direction {
        PacketDirection::Sending => {
            GLOBAL_STATE
                .last_tx_pkt
                .store(now_truncated, Ordering::SeqCst);
        }
        PacketDirection::Receiving => {
            // For each incoming packet, we suppose the network is "sane"
            // so "reset" last_tx_pkt.
            GLOBAL_STATE
                .last_tx_pkt
                .store(now_truncated, Ordering::SeqCst);
            GLOBAL_STATE
                .last_rx_pkt
                .store(now_truncated, Ordering::SeqCst);
        }
        _ => {}
    }
}

pub(crate) fn handle_ipv4_packet(
    source_mac: &MacAddr,
    interface: &NetworkInterface,
    ethernet: &EthernetPacket,
) {
    let interface_name = &interface.name;
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        let protocol = header.get_next_level_protocol();
        let direction = get_direction(source_mac, interface);

        // Don't handle local packet (if source is private and packet is receving; or if dest is private)
        if (header.get_source().is_private() && direction == PacketDirection::Receiving)
            || (header.get_source().is_private() && header.get_destination().is_private())
        {
            trace!(
                "[{}]: Don't handle local packets: {} > {}",
                interface_name,
                header.get_source(),
                header.get_destination()
            );
            return;
        }

        if !(protocol == IpNextHeaderProtocols::Udp && direction == PacketDirection::Sending)
            && ALLOWED_PROTOCOL.contains(&protocol)
        {
            trace!(
                "{}: update_state_rxtx: {} - {:?}",
                get_now_truncated(),
                protocol,
                direction
            );
            update_state_rxtx(&direction);
        }
    } else {
        error!("[{}]: Malformed IPv4 Packet", interface_name);
    }
}

pub(crate) fn handle_ipv6_packet(
    source_mac: &MacAddr,
    interface: &NetworkInterface,
    ethernet: &EthernetPacket,
) {
    let interface_name = &interface.name;
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        let protocol = header.get_next_header();
        let direction = get_direction(source_mac, interface);

        // Don't handle local packet (if source is private and packet is receving; or if dest is private)
        if (header.get_source().is_link_local() && direction == PacketDirection::Receiving)
            || (header.get_source().is_link_local() && header.get_destination().is_link_local())
        {
            trace!(
                "[{}]: Don't handle local packets: {} > {}",
                interface_name,
                header.get_source(),
                header.get_destination()
            );
            return;
        }

        if !(protocol == IpNextHeaderProtocols::Udp && direction == PacketDirection::Sending)
            && ALLOWED_PROTOCOL.contains(&protocol)
        {
            trace!(
                "{}: update_state_rxtx: {} - {:?}",
                get_now_truncated(),
                protocol,
                direction
            );
            update_state_rxtx(&direction);
        }
    } else {
        error!("[{}]: Malformed IPv6 Packet", interface_name);
    }
}

pub(crate) fn handle_ethernet_frame(interface: &NetworkInterface, ethernet: &EthernetPacket) {
    let source_mac = ethernet.get_source();

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => frame::handle_ipv4_packet(&source_mac, interface, ethernet),
        EtherTypes::Ipv6 => frame::handle_ipv6_packet(&source_mac, interface, ethernet),
        _ => {}
    }
}
