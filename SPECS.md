# Specifications

This is a SIP and media (PCMU only) proxy between an NTT Hikari Denwa (NGN) trunk, and a single downstream client. This crate needs only to support Linux-based OSes. This crate has many NTT specifics, explained below.

**Note**: This specification specifies the expected behaviors of our proxy implementation, and does not directly describe the contents of the official NTT specs, which is not published.

## Configuration
Programs that use this lib crate fetch NGN configuration info using DHCPv4/DHCPv6. That is covered in [ftth-dhcp](https://github.com/menhera-org/ftth-dhcp).

The user of this library configures the following (non exhaustive):

- The main number assigned by NTT
- Any additional numbers assigned by NTT (through DHCP, up to only four additional numbers are notified us; when there are more than 4 additional numbers, no such additional numbers are told us through DHCP).
    - Any numbers that are sent to us in `200 OK`s to our REGISTERs toward the trunk, in `P-Associated-URI` header (we extract the userinfo part of the SIP URIs), must be stored separately, and they are treated as additional numbers assigned by NTT.
- The trunk-leg network interface to bind to.
- The trunk-leg network address (that is assigned to us through DHCP). (port is UDP 5060)
- The trunk-side domain (that does not even need to resolve) to use in the trunk-leg URIs. e.g. `ntt-central.ne.jp` (this example is a false domain).
- The trunk-side SIP server's IP address (with UDP port 5060).
- The downstream-leg network interface to bind to.
- The downstream-leg network address to bind. (with UDP port 5060; this is configurable)

## Definitions
- **ALLOWED_IDENTITIES**: the main number configured, the additional numbers configured, and numbers sent to us in `P-Associated-URI` headers from the trunk (see above). If any of these numbers matches a number we want to call as, we can think that we are allowed to make calls as that number toward the trunk.
- **CALLED_PARTY_NUMBER**: userinfo part of `P-Called-Party-ID` headers in incoming calls from the trunk, with fall-back to `To:` header when no such header is present.

## Registrations
### Downstream client
- Downstream client needs to REGISTER itself to our proxy.
- We remember that client's contact as the downstream.
- We honor the `Expires` header sent by the client (including `0` clears).
- Authentication is optional (not usually used).
  - When auth is configured, 
- Registration interval is arbitrary, with a minimum of 30 seconds. We follow that timer to track registration states.
- `Contact` values' userinfo parts are arbitrary in REGISTERs toward our proxy.

### Registration to the trunk
- Our proxy also needs to REGISTER ourselves to the upstream SIP server.
- Request URI of the REGISTER request must be `sip:<trunk domain>`.
- rport parameter is not permitted.
- `Contact` header contains: `<sip:(random string)@(trunk interface address)>`. That random string is used throughout the lifetime of our proxy. (Re-launch of the proxy may change the value). `transport` parameters are forbidden inside this header.
- Registration expiration must be set to 3600 seconds. Re-REGISTERs happen after the seconds calculated by: `0.4 * <Expires header value on previous 200 OK to REGISTER>`.
- There should be no authentication requirements by the trunk. We don't authenticate our proxy against the trunk.
- `Via` header must contain: `SIP/2.0/UDP (trunk interface address):5060;branch=z9hG4bK(...)`, and must not contain `transport` parameters. Branch value must differ in re-REGISTERs every time.
- `From` header to the trunk must contain: `<sip:(main number)@(trunk domain)>;tag=(...)`. Tag must differ per (re-)registrations.
- `To` header to the trunk must contain: `<sip:(main number)@(trunk domain)>`.

## Incoming calls from the trunk
- Remember the `From:` header URIs on incoming calls, and use them as the `To:` headers sent to the trunk on that call.
- Remember the `To:` header URIs on incoming calls, and use them as the `From:` headers sent to the trunk on that call. Note that we need to manage the tags for them on our own.
- When no downstream client is registered, respond with appropriate temporary errors.
- Make the P-Called-Party-ID headers the authoritative sources of the called party numbers, with a fall-back to To headers.
- Extract the isub parameters of the SIP URI of the called party. That parameter is passed down to the client as-is.
- Extract the userinfo part of the SIP URI of the called party, and match that to **ALLOWED_IDENTITIES**. If no match was found, we respond with permanent error codes such as 404s. isub and other parameters are ignored when performing this matching.
- Call the downstream client with the called party number in the userinfo part of SIP URIs.
- We forward `P-Asserted-Identity` headers as-is from the trunk to the client.

## Outgoing calls from the client
- Make the SIP URI in the `P-Preferred-Identity` header the authoritative source of the caller ID the client wants to use, with reasonable fallbacks to other headers.
- If isub parameter is present in the caller ID the client presents to us, store that parameter (if not empty) and take no special action on that.
- Match the caller ID's userinfo part (this does NOT include the isub or other parameters) against the **ALLOWED_IDENTITIES**. If no match was found, force the use of the main number configured. Use this computed value inside `From` headers and `P-Preferred-Identity` headers.
- Extract the userinfo part of the INVITE sent to us from the client. The result is used as the called party number, with following notes:
    - If the userinfo part has `*` in the middle, treat the part before `*` as the called party number, with the part after `*` used as the isub parameter of the called party. This overwrites the isub parameter that may have been present before.
    - Allowed characters in the userinfo / isub parameter match what are representable with standard DTMF tones (0 to 9, `*` (`%2a`) and `#` (`%23`)). If other characters are found, reject the call with 404s. The exception is `-` character, which is just stripped out. When `*` and `#` are not correctly escaped we escape these characters on our own.
    - After the pre-processing described above is done, if the called party number becomes empty, reject the call.
- Construct the request line of the SIP request, as follows:
    - Method is `INVITE`
    - `SIP/2.0`
    - Request URI is: `sip:<called party userinfo>[;isub=<isub>]@<configured domain>`.
- `To:` headers of the INVITEs sent to the trunk mirror the Request URIs of those requests.
- Remember the tag in `From` header in responses from the trunk. And use that value as `To` headers' tag values we send during that call.
- `From` value we use for outgoing requests are remembered alongside the tags, and use that for messages we send to the trunk during that call. Userinfo parts pf `From` headers need not always match the main number, but can be any valid caller ID.
- No `rport` parameters are allowed inside `Via` headers. Via headers need to contain: `SIP/2.0/UDP (the trunk interface IP):5060;branch=z9hG4bK(...)`.
- `Route` header must have the values computed by combining:
    - `Path` header values in `200 OK` trunk responses to REGISTERs we send.
    - `Service-Route` values in `200 OK` trunk responses to REGISTERs we send.
- `Contact` header contains: `<sip:(random string)@(trunk interface address)>`.
- `From` header contains: `<sip:(main number)@(trunk domain)>`.
- We must not send `P-Asserted-Identity` headers to the trunk.

## Media proxying
- We must use the media port between 49152 and 65535 per NTT specs, and we default to 50000-60000.
- In SDP, `m=audio` line is required and PCMU is mandatory.
- In SDP, `a=sendrecv` must be set.
- In SDP, `a=ptime:20` is expected per NTT specs.
- We use `RTP/AVP`.
- We bind separate socket pairs for the trunk and the client legs, respectively.
- We always force media relay, and no direct media is allowed (SDP rewritten).
- Timeout (configurable)
