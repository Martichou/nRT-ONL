use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use pnet::util::MacAddr;

use crate::{frame, icmp, tcp, SharedState};

fn handle_transport_protocol(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
) {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            trace!(
                "[{}]: UDP Packet: {} > {}; length: {}",
                interface_name,
                source,
                destination,
                packet.len()
            );
        }
        IpNextHeaderProtocols::Tcp => {
            tcp::handle_tcp_packet(interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Icmp => {
            icmp::handle_icmp_packet(interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Icmpv6 => {
            icmp::handle_icmpv6_packet(interface_name, source, destination, packet)
        }
        _ => trace!(
            "[{}]: UKN {} packet: {} > {}; protocol: {:?} length: {}",
            interface_name,
            match source {
                IpAddr::V4(..) => "IPv4",
                _ => "IPv6",
            },
            source,
            destination,
            protocol,
            packet.len()
        ),
    }
}

fn update_state_rxtx(state: &SharedState, source_mac: &MacAddr, interface: &NetworkInterface) {
    let mac = interface.mac;

    // Determine if the packet is RX or TX
    // TODO - Only update if the outgoing packet is correct
    //		  otherwise, a no-response is expected.
    // TODO - Make a distinction between LAN/WAN packets.
    if let Some(rmac) = mac {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros();
        let now_truncated = now_unix as usize;

        info!("Normal Unix: {}", now_unix);
        info!("Trunca Unix: {}", now_truncated);

        if source_mac == &rmac {
            trace!(">>>>> PKT outgoing");
            state.last_tx_pkt.store(now_truncated, Ordering::Relaxed);
        } else {
            trace!("<<<<< PKT incoming");
            // For each incoming packet, we suppose the network is "sane"
            // so "reset" last_tx_pkt.
            state.last_tx_pkt.store(now_truncated, Ordering::Relaxed);
            state.last_rx_pkt.store(now_truncated, Ordering::Relaxed);
        }
    }
}

pub(crate) fn handle_ipv4_packet(
    state: &SharedState,
    source_mac: &MacAddr,
    interface: &NetworkInterface,
    ethernet: &EthernetPacket,
) {
    let interface_name = &interface.name;
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        // Only update if the packet is not "local"
        if !header.get_source().is_private() {
            update_state_rxtx(state, source_mac, interface);
        }

        handle_transport_protocol(
            interface_name,
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
        );
    } else {
        trace!("[{}]: Malformed IPv4 Packet", interface_name);
    }
}

pub(crate) fn handle_ipv6_packet(
    state: &SharedState,
    source_mac: &MacAddr,
    interface: &NetworkInterface,
    ethernet: &EthernetPacket,
) {
    let interface_name = &interface.name;
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        // Only update if the packet is not "local"
        // TODO - Once is_unicast_link_local is stable, use it
        update_state_rxtx(state, source_mac, interface);

        handle_transport_protocol(
            interface_name,
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
        );
    } else {
        trace!("[{}]: Malformed IPv6 Packet", interface_name);
    }
}

pub(crate) fn handle_ethernet_frame(
    state: &SharedState,
    interface: &NetworkInterface,
    ethernet: &EthernetPacket,
) {
    let source_mac = ethernet.get_source();

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => frame::handle_ipv4_packet(state, &source_mac, interface, ethernet),
        EtherTypes::Ipv6 => frame::handle_ipv6_packet(state, &source_mac, interface, ethernet),
        _ => {}
    }
}
