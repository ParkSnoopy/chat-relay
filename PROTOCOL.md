# Relay protocol

This is an IRC-like TCP relay, not the IRC wire protocol.

For a self-contained repository user guide, see [LLM_WIKI.md](./LLM_WIKI.md).

NDJSON, one JSON object per line. The server accepts plain TCP only on a
numeric loopback bind address. Any other bind requires a TLS certificate and
private key (`CHAT_RELAY_TLS_CERT`, `CHAT_RELAY_TLS_KEY`); peers must verify
the certificate and hostname. `CHAT_RELAY_AUTH_TOKEN` is mandatory: 64 random
hexadecimal characters. No secret is embedded in the container image.
`.env` is loaded from the working directory;
process environment and the CLI bind argument take precedence.

- Register: `{"type":"register","name":"alice","server_token":"..."}`.
  Names contain 1–32 ASCII letters, digits, hyphens or underscores. A successful
  registration receives `{"type":"welcome","user":"alice","token":"..."}`.
  The 128-bit per-name token can reclaim an active or recently disconnected
  name; every claim rotates it and closes the prior socket. Disconnected names
  remain reserved for their token holder for 10 minutes. Up to 1,024 token
  records are retained; an older disconnected reservation can be evicted when
  full. Any admitted peer can claim an unreserved name, so names are not
  durable identities.
- Message: `{"type":"msg","payload":...,"to":"bob"}` or
  `{"type":"msg","payload":...,"broadcast":true}`. `payload` can be any JSON
  value; the relay never interprets it. The server stamps `from`; direct
  messages reach only sender and recipient. Broadcast must be explicit per
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
