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

pub(super) fn decode_userinfo(value: &str) -> Option<Vec<char>> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut idx = 0;
    while idx < bytes.len() {
        match bytes[idx] {
            b'%' => {
                if idx + 2 >= bytes.len() {
                    return None;
                }
                let hex = &value[idx + 1..idx + 3];
                let parsed = u8::from_str_radix(hex, 16).ok()?;
                decoded.push(parsed as char);
                idx += 3;
            }
            b => {
                decoded.push(b as char);
                idx += 1;
            }
        }
    }
    Some(decoded)
}

pub(super) fn canonicalize_identity(value: &str) -> Option<String> {
    let decoded = decode_userinfo(value)?;
    let mut canonical = String::with_capacity(decoded.len());
    for ch in decoded {
        match ch {
            '0'..='9' => canonical.push(ch),
            '#' => canonical.push('#'),
            '-' => continue,
            _ => return None,
        }
    }
    if canonical.is_empty() {
        None
    } else {
        Some(canonical)
    }
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
