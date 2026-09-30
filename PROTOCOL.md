# Relay protocol

This is an IRC-like TCP relay, not the IRC wire protocol.

For a self-contained repository user guide, see [LLM_WIKI.md](./LLM_WIKI.md).

NDJSON, one JSON object per line. The default bind is `0.0.0.0:6697`.
`CHAT_RELAY_ALLOWED_HOST` is a comma-separated list of source IPs, hostnames,
or IPv4/IPv6 CIDRs. Hostnames resolve once at startup and match their resolved
IPs; no reverse DNS is used. An unset or empty list allows every source.
Filtering uses the TCP peer address, before TLS or registration, without
interface or VPN checks. Network isolation and access policy belong to the deployer.
TLS is optional on any bind: set both `CHAT_RELAY_TLS_CERT` and
`CHAT_RELAY_TLS_KEY` to enable it, or leave both empty for plaintext.
Setting only one path is a configuration error.
`.env` is loaded from the working directory;
process environment and the CLI bind argument take precedence.

- Register: `{"type":"register","name":"alice"}`.
  Names contain 1–32 Unicode alphanumeric characters, hyphens or underscores. A successful
  registration receives `{"type":"welcome","user":"alice","token":"..."}`.
  The 128-bit per-name token can reclaim an active or recently disconnected
  name; every claim rotates it and closes the prior socket. Disconnected names
  remain reserved for their token holder for 10 minutes. Up to 1,024 token
  records are retained; an older disconnected reservation can be evicted when
  full. Any admitted peer can claim an unreserved name, so names are not
  durable identities.
- Message: `{"type":"msg","payload":...,"to":["bob","carol"]}` or
  `{"type":"msg","payload":...,"broadcast":true}`. `payload` can be any JSON
  value; the relay never interprets it. `to` requires 1–64 valid names. If any
  name is unavailable, nobody receives the message. Duplicate names and the
  sender each receive one copy. The server stamps `from`; directed messages
  reach only the sender and named recipients. Broadcast must be explicit per
  message and does not persist between connections. Only routing fields are
  allowed outside `payload`. `CHAT_RELAY_MAX_CONTENT_SIZE` limits each incoming
  NDJSON line in bytes, excluding its newline (default 256 KiB); larger
  payloads require multiple messages. This is not a cumulative transfer limit.
  Both routes echo to sender.
- `{"type":"users"}` lists live names; `{"type":"ping"}` gets `pong`.
  Registration must finish within 10 seconds; registered connections close
  after 5 minutes without a complete line. TLS handshakes and blocked writes
  time out after 10 seconds. Slow receivers are disconnected; at most 64
  connections and eight queued messages per connection are admitted.

The relay does not inspect, log, or persist payloads. It cannot verify their
application-level properties; those belong outside the relay protocol.
