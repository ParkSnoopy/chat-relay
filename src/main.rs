//! chat-relay: opaque-payload relay server.
//!
//! NDJSON over TCP, with optional TLS. Route payloads without
//! interpreting their application-level format.

use std::{
    collections::{
        HashMap,
        HashSet,
    },
    fs::File,
    io::{
        self,
        BufReader,
    },
    net::{
        IpAddr,
        SocketAddr,
    },
    sync::{
        Arc,
        Mutex,
    },
    time::{
        Duration,
        Instant,
    },
};

use serde_json::{
    Value,
    json,
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{
        AsyncRead,
        AsyncWrite,
        AsyncWriteExt,
        BufWriter,
    },
    net::TcpListener,
    sync::{
        Semaphore,
        mpsc,
        watch,
    },
    time::timeout,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls,
};
use tokio_stream::StreamExt;
use tokio_util::codec::{
    FramedRead,
    LinesCodec,
};

// Bound frame size and queued memory per connection.
const MAX_LINE: usize = 256 * 1024;
const TX_BUFFER: usize = 8;
const MAX_CONNECTIONS: usize = 64;
const MAX_TOKENS: usize = 1024;
const TOKEN_TTL: Duration = Duration::from_secs(600);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Default)]
struct Registry {
    users: HashMap<String, Session>,
    tokens: HashMap<String, TokenRecord>,
}

struct Session {
    tx: mpsc::Sender<Arc<String>>,
    shutdown: watch::Sender<bool>,
}

struct TokenRecord {
    value: String,
    expires: Option<Instant>,
}

struct State {
    registry: Mutex<Registry>,
    max_content_size: usize,
}

struct AllowedHost {
    address: IpAddr,
    prefix: u32,
}

fn token() -> String {
    format!("{:032x}", rand::random::<u128>())
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().count() <= 32
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
}

fn content_size_limit(value: Option<&str>) -> usize {
    match value {
        None => MAX_LINE,
        Some(value) => {
            value
                .parse::<usize>()
                .ok()
                .filter(|size| *size > 0 && *size <= isize::MAX as usize)
                .expect("CHAT_RELAY_MAX_CONTENT_SIZE must be a positive byte count")
        }
    }
}

fn optional_env(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => Some(value),
        Ok(_) => None,
        Err(std::env::VarError::NotPresent) => None,
        Err(_) => panic!("{name} must be valid UTF-8"),
    }
}

impl AllowedHost {
    fn matches(&self, peer: IpAddr) -> bool {
        match (self.address, peer) {
            (IpAddr::V4(address), IpAddr::V4(peer)) => {
                let mask = u32::MAX.checked_shl(32 - self.prefix).unwrap_or(0);
                u32::from(address) & mask == u32::from(peer) & mask
            }
            (IpAddr::V6(address), IpAddr::V6(peer)) => {
                let mask = u128::MAX.checked_shl(128 - self.prefix).unwrap_or(0);
                u128::from(address) & mask == u128::from(peer) & mask
            }
            _ => false,
        }
    }
}

async fn allowed_hosts(value: &str) -> io::Result<Vec<AllowedHost>> {
    let mut hosts = Vec::new();
    for host in value.split(',').map(str::trim) {
        if let Some((address, prefix)) = host.split_once('/') {
            let address: IpAddr = address.parse().map_err(io::Error::other)?;
            let prefix: u32 = prefix.parse().map_err(io::Error::other)?;
            if prefix > if address.is_ipv4() { 32 } else { 128 } {
                return Err(io::Error::other("invalid host CIDR prefix"));
            }
            hosts.push(AllowedHost { address, prefix });
        } else {
            for address in tokio::net::lookup_host((host, 0)).await? {
                let address = address.ip();
                hosts.push(AllowedHost {
                    address,
                    prefix: if address.is_ipv4() { 32 } else { 128 },
                });
            }
        }
    }
    if hosts.is_empty() {
        return Err(io::Error::other("allowed hosts resolved to no addresses"));
    }
    Ok(hosts)
}

fn deliver(session: &Session, line: Arc<String>) {
    if session.tx.try_send(line).is_err() {
        let _ = session.shutdown.send(true);
    }
}

fn broadcast(registry: &Registry, line: Arc<String>) {
    for session in registry.users.values() {
        deliver(session, line.clone());
    }
}

fn reply(tx: &mpsc::Sender<Arc<String>>, message: Value) -> bool {
    tx.try_send(Arc::new(message.to_string())).is_ok()
}

async fn handle<S>(sock: S, peer: SocketAddr, state: Arc<State>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (rd, wr) = tokio::io::split(sock);
    let mut reader = FramedRead::new(rd, LinesCodec::new_with_max_length(state.max_content_size));
    let mut writer = BufWriter::new(wr);
    let (tx, mut rx) = mpsc::channel::<Arc<String>>(TX_BUFFER);
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    let mut writer_task = tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if !matches!(
                timeout(WRITE_TIMEOUT, async {
                    writer.write_all(line.as_bytes()).await?;
                    writer.write_all(b"\n").await?;
                    writer.flush().await
                })
                .await,
                Ok(Ok(()))
            ) {
                break;
            }
        }
        let _ = timeout(WRITE_TIMEOUT, writer.shutdown()).await;
    });

    let mut name: Option<String> = None;
    loop {
        let idle = if name.is_some() {
            Duration::from_secs(300)
        } else {
            Duration::from_secs(10)
        };
        let line = tokio::select! {
            biased;
            _ = shutdown_rx.changed() => break,
            _ = &mut writer_task => break,
            next = timeout(idle, reader.next()) => match next {
                Ok(Some(Ok(line))) => line,
                _ => break,
            },
        };
        let msg = match serde_json::from_str::<Value>(&line) {
            Ok(v) => v,
            Err(_) => {
                if !reply(&tx, json!({"type": "error", "error": "bad json"})) {
                    break;
                }
                continue;
            }
        };
        match msg.get("type").and_then(Value::as_str) {
            Some("register") => {
                if name.is_some() {
                    if !reply(&tx, json!({"type": "error", "error": "already registered"})) {
                        break;
                    }
                    continue;
                }
                if !msg.as_object().is_some_and(|fields| {
                    fields
                        .keys()
                        .all(|key| matches!(key.as_str(), "type" | "name" | "token"))
                }) || msg.get("token").is_some_and(|v| !v.is_string())
                {
                    if !reply(
                        &tx,
                        json!({"type": "error", "error": "invalid registration"}),
                    ) {
                        break;
                    }
                    continue;
                }
                let Some(req_name) = msg
                    .get("name")
                    .and_then(Value::as_str)
                    .filter(|s| valid_name(s))
                else {
                    if !reply(&tx, json!({"type": "error", "error": "invalid name"})) {
                        break;
                    }
                    continue;
                };
                let req_name = req_name.to_string();
                let req_token = msg.get("token").and_then(Value::as_str);
                let outcome = {
                    let mut registry = state.registry.lock().unwrap();
                    registry.tokens.retain(|_, record| {
                        record.expires.is_none_or(|until| until > Instant::now())
                    });
                    let valid = req_token.is_some_and(|t| {
                        registry.tokens.get(&req_name).is_some_and(|record| {
                            record.value.as_bytes().ct_eq(t.as_bytes()).into()
                        })
                    });
                    if registry.tokens.contains_key(&req_name) && !valid {
                        None
                    } else {
                        if !registry.tokens.contains_key(&req_name)
                            && registry.tokens.len() == MAX_TOKENS
                        {
                            // ponytail: bounded linear eviction; index only if token churn matters.
                            if let Some(oldest) = registry
                                .tokens
                                .iter()
                                .filter_map(|(name, record)| {
                                    record.expires.map(|until| (name.clone(), until))
                                })
                                .min_by_key(|(_, until)| *until)
                                .map(|(name, _)| name)
                            {
                                registry.tokens.remove(&oldest);
                            }
                        }
                        let tok = token();
                        registry.tokens.insert(
                            req_name.clone(),
                            TokenRecord {
                                value: tok.clone(),
                                expires: None,
                            },
                        );
                        if let Some(old) = registry.users.insert(
                            req_name.clone(),
                            Session {
                                tx: tx.clone(),
                                shutdown: shutdown_tx.clone(),
                            },
                        ) {
                            let _ = old.shutdown.send(true);
                        }
                        let queued = reply(
                            &tx,
                            json!({"type": "welcome", "user": req_name, "token": tok}),
                        );
                        if queued {
                            broadcast(
                                &registry,
                                Arc::new(json!({"type": "joined", "user": req_name}).to_string()),
                            );
                        }
                        Some(queued)
                    }
                };
                let Some(queued) = outcome else {
                    if !reply(&tx, json!({"type": "error", "error": "name taken"})) {
                        break;
                    }
                    continue;
                };
                name = Some(req_name.clone());
                println!("{peer} registered as {req_name}");
                if !queued {
                    break;
                }
            }
            Some("msg") => {
                let Some(from) = name.as_deref() else {
                    if !reply(&tx, json!({"type": "error", "error": "register first"})) {
                        break;
                    }
                    continue;
                };
                let to = msg.get("to").and_then(Value::as_array);
                let all = msg.get("broadcast") == Some(&Value::Bool(true));
                let valid = msg.as_object().is_some_and(|fields| {
                    fields
                        .keys()
                        .all(|key| matches!(key.as_str(), "type" | "payload" | "to" | "broadcast"))
                        && fields.contains_key("payload")
                }) && msg.get("broadcast").is_none_or(Value::is_boolean)
                    && msg.get("to").is_none_or(Value::is_array)
                    && (all != to.is_some())
                    && to.is_none_or(|names| {
                        !names.is_empty()
                            && names.len() <= MAX_CONNECTIONS
                            && names
                                .iter()
                                .all(|name| name.as_str().is_some_and(valid_name))
                    });
                if !valid {
                    if !reply(&tx, json!({"type": "error", "error": "invalid message"})) {
                        break;
                    }
                    continue;
                }
                let mut out = msg.clone();
                out["from"] = json!(from);
                let line = Arc::new(out.to_string());
                let result = {
                    let registry = state.registry.lock().unwrap();
                    if !registry
                        .users
                        .get(from)
                        .is_some_and(|session| session.tx.same_channel(&tx))
                    {
                        Some("register first")
                    } else if to.is_some_and(|names| {
                        names
                            .iter()
                            .any(|name| !registry.users.contains_key(name.as_str().unwrap()))
                    }) {
                        Some("user unavailable")
                    } else {
                        if all {
                            broadcast(&registry, line);
                        } else {
                            deliver(&registry.users[from], line.clone());
                            let mut sent = HashSet::new();
                            for recipient in to.unwrap().iter().filter_map(Value::as_str) {
                                if recipient != from && sent.insert(recipient) {
                                    deliver(&registry.users[recipient], line.clone());
                                }
                            }
                        }
                        None
                    }
                };
                if let Some(error) = result {
                    if !reply(&tx, json!({"type": "error", "error": error})) {
                        break;
                    }
                    if error == "register first" {
                        break;
                    }
                }
            }
            Some("users") => {
                if msg.as_object().is_none_or(|fields| fields.len() != 1) {
                    if !reply(&tx, json!({"type": "error", "error": "invalid message"})) {
                        break;
                    }
                    continue;
                }
                if name.is_none() {
                    if !reply(&tx, json!({"type": "error", "error": "register first"})) {
                        break;
                    }
                    continue;
                }
                let registry = state.registry.lock().unwrap();
                let active = name.as_deref().is_some_and(|name| {
                    registry
                        .users
                        .get(name)
                        .is_some_and(|session| session.tx.same_channel(&tx))
                });
                if !active {
                    break;
                }
                let users: Vec<&String> = registry.users.keys().collect();
                if !reply(&tx, json!({"type": "users", "users": users})) {
                    break;
                }
            }
            Some("ping") if name.is_some() => {
                if msg.as_object().is_none_or(|fields| fields.len() != 1) {
                    if !reply(&tx, json!({"type": "error", "error": "invalid message"})) {
                        break;
                    }
                    continue;
                }
                let registry = state.registry.lock().unwrap();
                if !registry
                    .users
                    .get(name.as_deref().unwrap())
                    .is_some_and(|session| session.tx.same_channel(&tx))
                    || !reply(&tx, json!({"type": "pong"}))
                {
                    break;
                }
            }
            _ => {
                if !reply(&tx, json!({"type": "error", "error": "unknown type"})) {
                    break;
                }
            }
        }
    }

    if let Some(name) = name.take() {
        let mut registry = state.registry.lock().unwrap();
        let owned = registry
            .users
            .get(&name)
            .is_some_and(|session| session.tx.same_channel(&tx));
        if owned {
            registry.users.remove(&name);
            if let Some(record) = registry.tokens.get_mut(&name) {
                record.expires = Some(Instant::now() + TOKEN_TTL);
            }
            broadcast(
                &registry,
                Arc::new(json!({"type": "left", "user": name}).to_string()),
            );
            println!("{peer} disconnected: {name}");
        }
    }
    if *shutdown_rx.borrow() || writer_task.is_finished() {
        writer_task.abort();
    } else {
        drop(tx);
        if timeout(WRITE_TIMEOUT, &mut writer_task).await.is_err() {
            writer_task.abort();
        }
    }
}

fn tls_acceptor(cert: &str, key: &str) -> io::Result<TlsAcceptor> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(cert)?))
        .collect::<io::Result<Vec<_>>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(key)?))?
        .ok_or_else(|| io::Error::other("missing TLS private key"))?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(io::Error::other)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[tokio::main]
async fn main() {
    if std::fs::exists(".env").expect("inspect .env") {
        dotenvy::from_filename(".env").unwrap_or_else(|_| panic!("invalid .env"));
    }

    let addr = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("CHAT_RELAY_ADDR").ok())
        .unwrap_or_else(|| "0.0.0.0:6697".to_string());
    let addr: SocketAddr = addr.parse().expect("CHAT_RELAY_ADDR must be IP:port");
    let hosts = match optional_env("CHAT_RELAY_ALLOWED_HOST") {
        Some(value) => allowed_hosts(&value).await.expect("resolve allowed hosts"),
        None => Vec::new(),
    };
    let tls = match (
        optional_env("CHAT_RELAY_TLS_CERT"),
        optional_env("CHAT_RELAY_TLS_KEY"),
    ) {
        (Some(cert), Some(key)) => {
            Some(tls_acceptor(&cert, &key).expect("load TLS certificate and key"))
        }
        (None, None) => None,
        _ => panic!("set both TLS certificate and key paths"),
    };
    let max_content_size = match std::env::var("CHAT_RELAY_MAX_CONTENT_SIZE") {
        Ok(value) => content_size_limit(Some(&value)),
        Err(std::env::VarError::NotPresent) => content_size_limit(None),
        Err(_) => panic!("CHAT_RELAY_MAX_CONTENT_SIZE must be valid UTF-8"),
    };
    let listener = TcpListener::bind(addr).await.expect("bind");
    println!("chat-relay listening on {addr}");
    let state = Arc::new(State {
        registry: Mutex::new(Registry::default()),
        max_content_size,
    });
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (sock, peer) = listener.accept().await.expect("accept");
        if !hosts.is_empty()
            && !hosts
                .iter()
                .any(|host| host.matches(peer.ip().to_canonical()))
        {
            continue;
        }
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let state = state.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Some(tls) = tls {
                if let Ok(Ok(sock)) = timeout(TLS_TIMEOUT, tls.accept(sock)).await {
                    handle(sock, peer, state).await;
                }
            } else {
                handle(sock, peer, state).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_names_and_content_limits_follow_the_wire_contract() {
        for name in [
            "보내는사람",
            "받는사람_2",
            "한글",
            "alice-123",
            &"가".repeat(32),
        ] {
            assert!(valid_name(name), "rejected {name}");
        }
        for name in ["", "bad name", "bad\nname", "<tag>", &"가".repeat(33)] {
            assert!(!valid_name(name), "accepted {name}");
        }
        assert_eq!(content_size_limit(None), MAX_LINE);
        assert_eq!(content_size_limit(Some("1048576")), 1048576);
        for value in ["", "0", "-1", "unlimited", "18446744073709551616"] {
            assert!(std::panic::catch_unwind(|| content_size_limit(Some(value))).is_err());
        }
    }

    #[tokio::test]
    async fn configured_content_limit_is_enforced_per_frame() {
        use tokio::io::AsyncWriteExt;
        let state = Arc::new(State {
            registry: Mutex::new(Registry::default()),
            max_content_size: 128,
        });
        let (client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(handle(server, "127.0.0.1:1".parse().unwrap(), state));
        let (reader, mut writer) = tokio::io::split(client);
        let mut reader = FramedRead::new(reader, LinesCodec::new());
        writer
            .write_all("{\"type\":\"register\",\"name\":\"한글\"}\n".as_bytes())
            .await
            .unwrap();
        let welcome: Value = serde_json::from_str(&reader.next().await.unwrap().unwrap()).unwrap();
        assert_eq!(welcome["type"], "welcome");
        assert_eq!(welcome["user"], "한글");
        let _ = reader.next().await;
        // Multiple bounded frames do not consume a cumulative size allowance.
        for _ in 0..40 {
            writer.write_all(b"{\"type\":\"ping\"}\n").await.unwrap();
            let pong: Value = serde_json::from_str(&reader.next().await.unwrap().unwrap()).unwrap();
            assert_eq!(pong["type"], "pong");
        }
        writer.write_all(&[b'x'; 129]).await.unwrap();
        writer.write_all(b"\n").await.unwrap();
        assert!(
            timeout(Duration::from_secs(1), reader.next())
                .await
                .unwrap()
                .is_none()
        );
        task.await.unwrap();
    }

    #[tokio::test]
    async fn host_filter_accepts_addresses_names_and_networks() {
        let hosts = allowed_hosts("127.0.0.1, localhost,192.168.0.0/24,fd00::/64")
            .await
            .unwrap();
        for (peer, expected) in [
            ("127.0.0.1", true),
            ("::1", true),
            ("127.0.0.2", false),
            ("192.168.0.0", true),
            ("192.168.0.255", true),
            ("192.168.1.0", false),
            ("fd00::123", true),
            ("fd00:0:0:1::1", false),
        ] {
            assert_eq!(
                hosts.iter().any(|host| host.matches(peer.parse().unwrap())),
                expected,
                "{peer}"
            );
        }
        for value in [
            "192.168.0.0/33",
            "fd00::/129",
            "127.0.0.1,",
            "",
            "bad/network",
        ] {
            assert!(allowed_hosts(value).await.is_err(), "{value}");
        }
        for (network, peer) in [
            ("0.0.0.0/0", "8.8.8.8"),
            ("::/0", "2001:db8::1"),
            ("192.168.0.1/32", "192.168.0.1"),
            ("::1/128", "::1"),
        ] {
            assert!(allowed_hosts(network).await.unwrap()[0].matches(peer.parse().unwrap()));
        }
    }

    #[test]
    fn slow_recipient_does_not_block_others() {
        let (slow_tx, _slow_rx) = mpsc::channel(1);
        let (slow_shutdown, slow_closed) = watch::channel(false);
        let (fast_tx, mut fast_rx) = mpsc::channel(2);
        let (fast_shutdown, _fast_closed) = watch::channel(false);
        let registry = Registry {
            users: HashMap::from([
                (
                    "slow".into(),
                    Session {
                        tx: slow_tx,
                        shutdown: slow_shutdown,
                    },
                ),
                (
                    "fast".into(),
                    Session {
                        tx: fast_tx,
                        shutdown: fast_shutdown,
                    },
                ),
            ]),
            tokens: HashMap::new(),
        };
        broadcast(&registry, Arc::new("first".into()));
        broadcast(&registry, Arc::new("second".into()));
        assert!(*slow_closed.borrow());
        assert_eq!(fast_rx.try_recv().unwrap().as_str(), "first");
        assert_eq!(fast_rx.try_recv().unwrap().as_str(), "second");
    }
}
