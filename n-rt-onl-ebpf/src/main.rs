#![no_std]
#![no_main]

use core::net::Ipv4Addr;

use aya_bpf::{
	helpers::bpf_ktime_get_ns,
	bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
	macros::{classifier, map},
	maps::HashMap,
	programs::TcContext
};
use aya_log_ebpf::{trace, debug};

use network_types::{
    eth::{EthHdr, EtherType}, ip::{IpProto, Ipv4Hdr}
};

#[derive(PartialEq)]
enum PktDirection {
    Egress = 0,
    Ingress,
}

static SUPPORTED_SENT_PROTO: [IpProto; 4] = [IpProto::Tcp, IpProto::Udp, IpProto::Icmp, IpProto::Ipv6Icmp];

#[map]
static PKT_TIMESTAMP: HashMap<u8, u64> = HashMap::<u8, u64>::with_max_entries(2, 0);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

fn try_n_rt_onl_ebpf(ctx: TcContext, dir: PktDirection) -> Result<i32, ()> {
	let is_sending = dir == PktDirection::Egress;
	let eth_hdr: EthHdr = ctx.load(0).map_err(|_| ())?;

	// If the pkt is a Ipv4, continue, otherwise, PASS
    match eth_hdr.ether_type {
        EtherType::Ipv4 => {},
        _ => {
			trace!(&ctx, "Skipping: not Ipv4");
			return Ok(TC_ACT_PIPE)
		},
    }

	let ipv4_hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let source_addr = u32::from_be(ipv4_hdr.src_addr);
	let dest_addr = u32::from_be(ipv4_hdr.dst_addr);

	let ip4_src = Ipv4Addr::from(source_addr);
	let ip4_dst = Ipv4Addr::from(dest_addr);

	// Don't handle pkt if src is private when we're receiving the pkt or if both are private
	if (ip4_src.is_private() && !is_sending) || (ip4_src.is_private() && ip4_dst.is_private()) {
		trace!(&ctx, "Skipping: private to private");
		return Ok(TC_ACT_PIPE);
	}

	// Don't handle broadcast
	if ip4_src.is_broadcast() || ip4_dst.is_broadcast() {
		trace!(&ctx, "Skipping: broadcast");
		return Ok(TC_ACT_PIPE);
	}

	let protocol = ipv4_hdr.proto;
	if !SUPPORTED_SENT_PROTO.contains(&protocol) {
		debug!(&ctx, "Unsupported protocol: {}", protocol as u8);
	}

	if is_sending && SUPPORTED_SENT_PROTO.contains(&protocol) {
		let _ = PKT_TIMESTAMP.insert(&1, unsafe { &bpf_ktime_get_ns() }, 0);
	} else if !is_sending {
		// For each incoming packet, we suppose the network is "sane" so "reset" last_tx_pkt.
		let _ = PKT_TIMESTAMP.insert(&0, unsafe { &bpf_ktime_get_ns() }, 0);
		let _ = PKT_TIMESTAMP.insert(&1, unsafe { &bpf_ktime_get_ns() }, 0);
	}

	trace!(
		&ctx,
		"{} - Packet: {:i} > {:i}",
		protocol as u8,
		source_addr,
		dest_addr,
	);

    Ok(TC_ACT_PIPE)
}

#[classifier]
pub fn n_rt_onl_ebpf_ingress(ctx: TcContext) -> i32 {
    match try_n_rt_onl_ebpf(ctx, PktDirection::Ingress) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

#[classifier]
pub fn n_rt_onl_ebpf_egress(ctx: TcContext) -> i32 {
    match try_n_rt_onl_ebpf(ctx, PktDirection::Egress) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}