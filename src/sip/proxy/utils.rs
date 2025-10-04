use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use ftth_rsipstack::rsip;
use rsip::Param;
use rsip::typed;

pub(super) fn format_socket_for_sip(addr: &SocketAddr) -> String {
    match addr.ip() {
        std::net::IpAddr::V6(ipv6) => format!("[{}]:{}", ipv6, addr.port()),
        std::net::IpAddr::V4(ipv4) => format!("{}:{}", ipv4, addr.port()),
    }
}

pub(super) fn strip_rport_param(via: &mut typed::Via) {
    via.params.retain(|param| {
        if let Param::Other(name, _) = param {
            !name.value().eq_ignore_ascii_case("rport")
        } else {
            true
        }
    });
}

pub(super) fn md5_hex(bytes: &[u8]) -> String {
    format!("{:032x}", md5::compute(bytes))
}

pub(super) fn generate_cnonce() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    format!("{:x}", now.as_nanos())
}

pub(super) fn constant_time_eq(lhs: &[u8], rhs: &[u8]) -> bool {
    if lhs.len() != rhs.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in lhs.iter().zip(rhs.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}
