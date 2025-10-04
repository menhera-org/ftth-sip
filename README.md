# ftth-sip
SIP proxy / media proxy component for FTTH suite of CPE software, in Rust.

## Quick start

The example harness wires the proxy together with a single downstream PBX. The
downstream client now authenticates using SIP Digest, so provide both the
expected username and password when launching the test server:

```
cargo run --example ftth-sip-test-server -- \
    --upstream-registrar-uri sip:example.ngn.jp \
    --upstream-domain example.ngn.jp \
    --upstream-trunk-ip 192.0.2.100 \
    --upstream-default-identity 0298284147 \
    --downstream-username asterisk \
    --downstream-password secret
```

Runtime configuration embeds the downstream credentials in
`AllowedUserAgent.password`, enabling the proxy to challenge REGISTER and
in-dialog requests arriving from the LAN side while relaying them upstream once
verified. When relaying toward the upstream NGN trunk the proxy rewrites SDP to
offer PCMU (payload 0) exclusively, matching the officially supported
capabilities for many deployments.
