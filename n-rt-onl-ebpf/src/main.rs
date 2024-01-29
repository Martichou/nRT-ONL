#![no_std]
#![no_main]

use aya_bpf::{
	helpers::bpf_ktime_get_ns,
	bindings::xdp_action,
	macros::{xdp, map},
	maps::HashMap,
	programs::XdpContext
};
use aya_log_ebpf::{trace, debug};

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType}, ip::{IpProto, Ipv4Hdr}
};

static SUPPORTED_SENT_PROTO: [IpProto; 4] = [IpProto::Tcp, IpProto::Udp, IpProto::Icmp, IpProto::Ipv6Icmp];

#[map]
static PKT_TIMESTAMP: HashMap<u8, u64> = HashMap::<u8, u64>::with_max_entries(2, 0);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
fn is_private(ip: u32) -> bool {
    let a = (ip >> 24) as u8;
    let b = (ip >> 16) as u8;

    match a {
        10 => true,
        172 if b >= 16 && b <= 31 => true,
        192 if b == 168 => true,
        _ => false,
    }
}

fn try_n_rt_onl_ebpf(ctx: XdpContext) -> Result<u32, ()> {
    let eth_hdr: *const EthHdr = ptr_at(&ctx, 0)?;

	// If the packet is a Ipv4, continue, otherwise, PASS
    match unsafe { (*eth_hdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4_hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be(unsafe { (*ipv4_hdr).src_addr });
	let dest_addr = u32::from_be(unsafe { (*ipv4_hdr).dst_addr });

	let source_private = is_private(source_addr);
	let dest_private = is_private(dest_addr);

	// TODO - For now assume that if the source IP is private, we're sending a packet
	let is_sending = source_private;

	// Don't handle packets if both are private
	if (source_private && !is_sending) || (source_private && dest_private) {
		return Ok(xdp_action::XDP_PASS);
	}

	let protocol = unsafe { (*ipv4_hdr).proto };

	if !SUPPORTED_SENT_PROTO.contains(&protocol) {
		debug!(
			&ctx,
			"Unsupported protocol: {}",
			protocol as u8
		);
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
		"{} - {} Packet: {:i} > {:i}",
		protocol as u8,
		is_sending as u8,
		source_addr,
		dest_addr,
	);

    Ok(xdp_action::XDP_PASS)
}

#[xdp]
pub fn n_rt_onl_ebpf(ctx: XdpContext) -> u32 {
    match try_n_rt_onl_ebpf(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}