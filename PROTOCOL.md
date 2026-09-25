# Relay protocol

This is an IRC-like TCP relay, not the IRC wire protocol.

For a self-contained repository user guide, see [LLM_WIKI.md](./LLM_WIKI.md).

NDJSON, one JSON object per line. The server accepts plain TCP only on a
numeric loopback bind address. Any other bind requires a TLS certificate and
private key (`CHAT_RELAY_TLS_CERT`, `CHAT_RELAY_TLS_KEY`); peers must verify
the certificate and hostname. By default `CHAT_RELAY_AUTH_TOKEN` is required:
64 random hexadecimal characters. `CHAT_RELAY_REQUIRE_AUTH_TOKEN=false`
disables this check and rejects the `server_token` registration field. For non-loopback binds in that mode, either set `CHAT_RELAY_VPN_ONLY=true`
with `CHAT_RELAY_VPN_INTERFACE` or explicitly opt out of ingress protection
with `CHAT_RELAY_ALLOW_UNAUTHENTICATED_NON_LOOPBACK=true`. The latter does not
enforce VPN isolation and must not be used as evidence of VPN-only admission.
VPN-only mode requires a specific non-loopback listener address and Linux
interface binding (`SO_BINDTODEVICE`); the listener fails closed if the
interface is unavailable. For direct VPN ingress the interface must be a
tunnel device. For a separate gateway, set `CHAT_RELAY_VPN_GATEWAY_IP` to its
exact private source address and bind to a private address on the selected
ingress interface. Only that source can reach TLS/registration. The gateway
must itself exclude off-VPN traffic; the relay cannot verify its upstream
policy. TLS remains mandatory for either non-loopback mode. No secret is
embedded in the container image.
`.env` is loaded from the working directory;
process environment and the CLI bind argument take precedence.

- Register: `{"type":"register","name":"alice","server_token":"..."}`
  when admission is enabled; omit `server_token` when it is disabled.
  Names contain 1–32 ASCII letters, digits, hyphens or underscores. A successful
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
  allowed outside `payload`. Each NDJSON line is at most 256 KiB; larger
  payloads require multiple messages. Both routes echo to sender.
- `{"type":"users"}` lists live names; `{"type":"ping"}` gets `pong`.
  Registration must finish within 10 seconds; registered connections close
  after 5 minutes without a complete line. TLS handshakes and blocked writes
  time out after 10 seconds. Slow receivers are disconnected; at most 64
  connections and eight queued messages per connection are admitted.

The relay does not inspect, log, or persist payloads. It cannot verify their
application-level properties; those belong outside the relay protocol.
