use std::net::IpAddr;

use pnet::packet::{
    icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes},
    icmpv6::Icmpv6Packet,
};

pub fn handle_icmp_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
) {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                trace!(
                    "[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                    interface_name,
                    source,
                    destination,
                    echo_reply_packet.get_sequence_number(),
                    echo_reply_packet.get_identifier()
                );
            }
            IcmpTypes::EchoRequest => {
                let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                trace!(
                    "[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                    interface_name,
                    source,
                    destination,
                    echo_request_packet.get_sequence_number(),
                    echo_request_packet.get_identifier()
                );
            }
            _ => trace!(
                "[{}]: ICMP packet {} -> {} (type={:?})",
                interface_name,
                source,
                destination,
                icmp_packet.get_icmp_type()
            ),
        }
    }
}

pub fn handle_icmpv6_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
) {
    let icmpv6_packet = Icmpv6Packet::new(packet);
    if let Some(icmpv6_packet) = icmpv6_packet {
        trace!(
            "[{}]: ICMPv6 packet {} -> {} (type={:?})",
            interface_name,
            source,
            destination,
            icmpv6_packet.get_icmpv6_type()
        )
    }
}
