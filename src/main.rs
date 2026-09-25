//! chat-relay: opaque-payload relay server.
//!
//! NDJSON over TCP on loopback, TLS elsewhere. Route payloads without
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
    net::{IpAddr, SocketAddr},
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
#[cfg(target_os = "linux")]
use tokio::net::TcpSocket;
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
    auth_token: Option<String>,
}

struct VpnIngress {
    interface: String,
    gateway: Option<IpAddr>,
}

fn token() -> String {
    format!("{:032x}", rand::random::<u128>())
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn bool_env(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(value) if value == "true" => true,
        Ok(value) if value == "false" => false,
        Err(std::env::VarError::NotPresent) => default,
        _ => panic!("{name} must be true or false"),
    }
}

fn private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private(),
        IpAddr::V6(ip) => ip.is_unique_local(),
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

fn vpn_ingress(addr: SocketAddr, enabled: bool) -> Option<VpnIngress> {
    let interface = optional_env("CHAT_RELAY_VPN_INTERFACE");
    let gateway = optional_env("CHAT_RELAY_VPN_GATEWAY_IP");
    if !enabled {
        assert!(
            interface.is_none() && gateway.is_none(),
            "VPN ingress settings require CHAT_RELAY_VPN_ONLY=true"
        );
        return None;
    }
    assert!(
        !addr.ip().is_unspecified() && !addr.ip().is_loopback(),
        "VPN-only bind must select a non-loopback IP"
    );
    let interface = interface.expect("CHAT_RELAY_VPN_INTERFACE required");
    assert!(
        !interface.is_empty()
            && interface.len() <= 15
            && !interface.starts_with('.')
            && interface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')),
        "invalid VPN interface name"
    );
    let gateway = gateway
        .map(|ip| ip.parse::<IpAddr>().expect("invalid CHAT_RELAY_VPN_GATEWAY_IP"));
    if let Some(gateway) = gateway {
        assert!(
            gateway.is_ipv4() == addr.ip().is_ipv4(),
            "VPN gateway and listener IP families differ"
        );
        assert!(
            private_ip(addr.ip()) && private_ip(gateway),
            "gateway ingress requires private listener and gateway IPs"
        );
    }
    Some(VpnIngress { interface, gateway })
}

async fn bind_listener(addr: SocketAddr, ingress: Option<&VpnIngress>) -> io::Result<TcpListener> {
    if let Some(ingress) = ingress {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;

            let socket = if addr.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            if ingress.gateway.is_none() {
                // SIOCGIFHWADDR reads the interface in this socket's network namespace.
                let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
                for (target, source) in request.ifr_name.iter_mut().zip(ingress.interface.bytes()) {
                    *target = source as libc::c_char;
                }
                if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFHWADDR, &mut request) } < 0 {
                    return Err(io::Error::last_os_error());
                }
                if unsafe { request.ifr_ifru.ifru_hwaddr.sa_family } != libc::ARPHRD_NONE {
                    return Err(io::Error::other("direct VPN ingress requires a tunnel interface"));
                }
            }
            socket.bind_device(Some(ingress.interface.as_bytes()))?;
            socket.bind(addr)?;
            return socket.listen(1024);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = ingress;
            return Err(io::Error::other("VPN ingress requires Linux SO_BINDTODEVICE"));
        }
    }
    TcpListener::bind(addr).await
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
    let mut reader = FramedRead::new(rd, LinesCodec::new_with_max_length(MAX_LINE));
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
                if let Some(auth_token) = state.auth_token.as_ref()
                    && !msg
                        .get("server_token")
                        .and_then(Value::as_str)
                        .is_some_and(|t| t.as_bytes().ct_eq(auth_token.as_bytes()).into())
                {
                    let _ = reply(&tx, json!({"type": "error", "error": "unauthorized"}));
                    break;
                }
                if !msg.as_object().is_some_and(|fields| {
                    fields.keys().all(|key| {
                        matches!(key.as_str(), "type" | "name" | "token")
                            || (key == "server_token" && state.auth_token.is_some())
                    })
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
    let require_auth_token = bool_env("CHAT_RELAY_REQUIRE_AUTH_TOKEN", true);
    let allow_unauthenticated_non_loopback =
        bool_env("CHAT_RELAY_ALLOW_UNAUTHENTICATED_NON_LOOPBACK", false);
    let auth_token = if require_auth_token {
        let auth_token =
            std::env::var("CHAT_RELAY_AUTH_TOKEN").expect("CHAT_RELAY_AUTH_TOKEN required");
        assert!(
            auth_token.len() == 64 && auth_token.bytes().all(|b| b.is_ascii_hexdigit()),
            "CHAT_RELAY_AUTH_TOKEN must be 64 hexadecimal characters"
        );
        Some(auth_token)
    } else {
        None
    };
    let addr = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("CHAT_RELAY_ADDR").ok())
        .unwrap_or_else(|| "127.0.0.1:6697".to_string());
    let addr: SocketAddr = addr.parse().expect("CHAT_RELAY_ADDR must be IP:port");
    let vpn_only = bool_env("CHAT_RELAY_VPN_ONLY", false);
    let ingress = vpn_ingress(addr, vpn_only);
    assert!(
        require_auth_token || addr.ip().is_loopback() || allow_unauthenticated_non_loopback || vpn_only,
        "token-free non-loopback bind requires VPN-only ingress or CHAT_RELAY_ALLOW_UNAUTHENTICATED_NON_LOOPBACK=true"
    );
    let tls = match (
        std::env::var("CHAT_RELAY_TLS_CERT"),
        std::env::var("CHAT_RELAY_TLS_KEY"),
    ) {
        (Ok(cert), Ok(key)) if !cert.is_empty() && !key.is_empty() => {
            Some(tls_acceptor(&cert, &key).expect("load TLS certificate and key"))
        }
        (Ok(cert), Ok(key)) if cert.is_empty() && key.is_empty() && addr.ip().is_loopback() => {
            None
        }
        (Err(std::env::VarError::NotPresent), Err(std::env::VarError::NotPresent))
            if addr.ip().is_loopback() =>
        {
            None
        }
        _ => panic!("TLS certificate and key required for non-loopback bind"),
    };
    let listener = bind_listener(addr, ingress.as_ref()).await.expect("bind ingress");
    println!("chat-relay listening on {addr}");
    let state = Arc::new(State {
        registry: Mutex::new(Registry::default()),
        auth_token,
    });
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (sock, peer) = listener.accept().await.expect("accept");
        if ingress
            .as_ref()
            .and_then(|vpn| vpn.gateway)
            .is_some_and(|gateway| peer.ip() != gateway)
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
