use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use std::net::IpAddr;

use crate::{frame, icmp, tcp};

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

pub fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
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

pub fn handle_ipv6_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
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

pub fn handle_ethernet_frame(interface: &NetworkInterface, ethernet: &EthernetPacket) {
    let interface_name = &interface.name;

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => frame::handle_ipv4_packet(interface_name, ethernet),
        EtherTypes::Ipv6 => frame::handle_ipv6_packet(interface_name, ethernet),
        _ => {}
    }
}
