# ftth-sip
SIP proxy / media proxy component for FTTH suite of CPE software, in Rust.

## NTT NGN usage
```bash
# Fetch information with `ftth-dhcp` and configure interfaces with `ftth-rtnl`.
# As root
ftth-sip-test-server --upstream-registrar-uri sip:{ntt_domain} --upstream-domain {ntt_domain} --upstream-trunk-ip {sip_server} --downstream-username asterisk --downstream-bind-addr {lan_ip} --downstream-bind-port 5060 --upstream-default-identity {ntt_main_number} --allowed-identity {ntt_additional_numner} --allowed-identity {...} --upstream-bind-addr {ngn_dhcp4_addr} --upstream-bind-port 5060 --upstream-interface {ngn_interface} --media-port-min 50000 --media-port-max 60000 --media-upstream-interface {ngn_interface} --downstream-default-user s --registration-refresh 3600
```

## Quick start

The example harness wires the proxy together with a single downstream PBX. The
downstream client now authenticates using SIP Digest, so provide the expected
username and (optionally) password when launching the test server:

```
cargo run --example ftth-sip-test-server -- \
    --upstream-registrar-uri sip:example.ngn.jp \
    --upstream-domain example.ngn.jp \
    --upstream-trunk-ip 192.0.2.100 \
    --upstream-default-identity 0298284147 \
    --downstream-username asterisk \
    [--downstream-password secret]
```

Runtime configuration embeds the downstream credentials in
`AllowedUserAgent.password`; omit the password to disable LAN-side
authentication. When present the proxy challenges REGISTER and in-dialog
requests arriving from the LAN side before relaying them upstream.
When relaying toward the upstream NGN trunk the proxy rewrites SDP to
offer PCMU (payload 0) exclusively, matching the officially supported
capabilities for many deployments. The proxy will also trigger an upstream
re-REGISTER whenever the downstream PBX refreshes its registration or when
INVITE transactions time out, helping keep the trunk binding fresh.
