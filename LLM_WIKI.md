# chat-relay: standalone guide for repository users

This repository builds an IRC-like Rust TCP relay, not an IRC-protocol server.
Each connection registers a name; registered peers can address another live
name or explicitly broadcast to all live names on that server. Messages are
newline-delimited JSON (NDJSON). The relay handles admission, routing, and
connection limits. `payload` is arbitrary JSON, forwarded without meaning.
There is no account database, message history, or application-specific payload
format. This document is sufficient to run the relay and implement a peer;
the linked files at the end are optional references.

## Run it

Build/run with a Rust toolchain supporting edition 2024. On the local machine:

```sh
cargo run --locked -- 127.0.0.1:6697
```

The command-line address takes precedence over `CHAT_RELAY_ADDR`; otherwise
the default is `0.0.0.0:6697`. Addresses must be numeric IP:port values,
not hostnames. The server optionally loads `.env` from its working directory;
pre-existing process environment variables take precedence. The example
configuration is [`.env.example`](./.env.example).
`CHAT_RELAY_ALLOWED_HOST` accepts comma-separated source IPs, hostnames, and
IPv4/IPv6 CIDRs. Hostnames resolve once at startup; matching uses the TCP peer
IP, not reverse DNS or a client-supplied name. Unset or empty means all hosts
are allowed. Invalid entries fail startup. No interface or VPN policy is enforced;
network isolation and security are the deployer's responsibility.
TLS is optional on every bind. Both paths enable TLS; both empty or absent
select plaintext. Supplying only one path fails startup.

To check a running relay, run the repository smoke test in another terminal:

```sh
python3 tests/relay_smoke.py
```

The server's `.env` is not loaded by the Python test. For a test TLS listener,
set `TEST_RELAY_HOST` and `TEST_RELAY_PORT` to its address and port, and
`TEST_RELAY_TLS_CERT` to the certificate trusted by the test; it verifies
`localhost`.

The [Dockerfile](./Dockerfile) builds `linux/amd64` in the publication workflow
and starts the binary as UID/GID 65532. Build locally with
`docker build -t chat-relay:local .`. In a container, set
`CHAT_RELAY_ADDR=0.0.0.0:6697` (loopback inside the container is unreachable
through a published port). Host filtering sees the source IP delivered by the
container network. When using TLS, mount its files readably for UID 65532.
Port exposure and network protection are deployment decisions.
The [publication workflow](./.github/workflows/publish-container.yml) pushes
`ghcr.io/<lowercase-owner>/<lowercase-repo>` for pushed `v*` SemVer tags,
with version and major.minor tags; it does not publish `latest`.

## What runs inside the server

One Tokio listener accepts sockets, caps active connections with a semaphore,
and performs a timed TLS handshake when configured. Each admitted connection
has a framed JSON reader and a separate writer fed by a bounded channel. A
shared in-memory registry maps live names to writer channels and stores
name-reclaim tokens, which expire after disconnect. Registration, reclaim,
and routing decisions take the registry lock so simultaneous name claims
have one winner. Sending to a full outgoing queue disconnects that slow peer
instead of holding up others. Disconnect removes a live name, starts its
reservation expiry, and announces `left`. Restarting clears the registry and
all queued messages. Server logs contain addresses and names, not payloads.

## Wire contract

Open one TCP connection (TLS when configured), send one JSON object per line,
and read events on the same connection. A complete line is required for each
request. The first operation is registration:

```json
{"type":"register","name":"alice"}
```

Names are 1–32 Unicode alphanumeric characters, `_` or `-`. Successful
registration sends `{"type":"welcome","user":"alice","token":"..."}`.
The returned per-name `token` is a 128-bit secret for reclaiming that name. Retain the newest
returned token if reclaim is needed. A peer already holding a reclaim token
registers with the same fields plus `"token":"<newest-name-token>"`.
Reclaim rotates the name token and closes its previous connection, including
when that connection is still active. A claimed name stays reserved for its
token holder for 10 minutes after disconnect; after that it becomes free.
All tokens and registrations exist only in server memory. A restart loses
them. Names are not durable identities: any admitted peer can claim an
unreserved name.

After `welcome`, a directed message has an array of recipients:

```json
{"type":"msg","to":["bob","carol"],"payload":{"example":[1,true]}}
```

For every recipient currently registered on this server, a broadcast has an
explicit flag on **that message** (there is no connection-wide broadcast
setting):

```json
{"type":"msg","broadcast":true,"payload":"opaque-value"}
```

Specify exactly one of `to` or `broadcast:true`; no route is implicit. `to`
must contain 1–64 valid names. If any named user is unavailable, the entire
request fails without delivery. Duplicate names are delivered once. The
sender receives its own message, and the server adds `"from":"alice"` to
each delivered message. A directed message reaches only sender and named
recipients; listing the sender also delivers just one copy. A broadcast reaches
every registered connection, including its sender. Only `type`, `payload`, `to`,
and `broadcast` belong on the outer message object. `payload` is required
but may be any JSON value, including `null`. Put all application-defined
structure inside it. The server parses JSON framing but does not validate
payload semantics, confidentiality, or suitability for a particular peer.
The server does not log or persist payloads; they still pass through its
memory and transport, so relay use alone does not provide content secrecy.

Other commands after registration are `{"type":"users"}` (reply:
`{"type":"users","users":["alice","bob"]}`; order unspecified) and
`{"type":"ping"}` (reply: `{"type":"pong"}`). Connections also receive
`{"type":"joined","user":"bob"}` and
`{"type":"left","user":"bob"}` when names join or disconnect. The newly
registered peer can receive its own `joined` event after `welcome`.

## Errors, limits, and retries

Errors are `{"type":"error","error":"..."}`. Bad JSON returns `bad json`
without closing the connection. Malformed registration, invalid names,
reserved names without their current token, and invalid messages return
`invalid registration`, `invalid name`, `name taken`, and `invalid message`
respectively. A directed message to a missing recipient returns
`user unavailable` and is not queued for later. `register first` applies to
messages and `users` sent before registration. A repeated registration
returns `already registered`; unrecognized requests return `unknown type`.
Only `type`, `name`, and optional `token` belong in registration.
Other invalid requests normally leave the connection open; EOF, timeouts,
oversized lines, and slow readers close it. Delivery after a disconnected
send is unknown: a sender echo does not confirm recipient receipt, and the
protocol has no automatic retry.

`CHAT_RELAY_MAX_CONTENT_SIZE` limits incoming NDJSON lines in bytes excluding
the newline (default 256 KiB). It is not a total file or transfer limit;
callers split larger payloads into independently routable messages.
An unregistered connection has 10
seconds to send a complete line; a registered connection is idle-closed after
5 minutes without a complete line (send `ping` if needed). TLS handshakes and
blocked writes time out after 10 seconds. At most 64 connections are admitted;
excess connections are dropped. Each connection has an eight-message outgoing
queue; a slow receiver is disconnected rather than stalling others. At most
1,024 name-token records are retained; an older disconnected reservation may
be evicted when the table fills. Messages are not retained for offline peers.

## Repository map (optional)

- [Rust manifest](./Cargo.toml) and [lockfile](./Cargo.lock): build inputs.
- [Server implementation](./src/main.rs): listener, TLS, registry, routing.
- [Protocol summary](./PROTOCOL.md): compact wire reference.
- [Smoke test](./tests/relay_smoke.py): live loopback/TLS protocol checks.
- [Example environment](./.env.example): supported settings.
- [Dockerfile](./Dockerfile) and [publication workflow](./.github/workflows/publish-container.yml): container distribution.