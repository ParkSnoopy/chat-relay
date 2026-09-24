//! chat-relay: opaque-payload relay server.
//!
//! NDJSON over TCP on loopback, TLS elsewhere. Route payloads without
//! interpreting their application-level format.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, rustls};
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, LinesCodec};

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
    auth_token: String,
}

fn token() -> String {
    format!("{:032x}", rand::random::<u128>())
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
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
            if !matches!(timeout(WRITE_TIMEOUT, async {
                    writer.write_all(line.as_bytes()).await?;
                    writer.write_all(b"\n").await?;
                    writer.flush().await
                }).await, Ok(Ok(()))) {
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
                if !msg.get("server_token").and_then(Value::as_str).is_some_and(|t| {
                    t.as_bytes().ct_eq(state.auth_token.as_bytes()).into()
                }) {
                    let _ = reply(&tx, json!({"type": "error", "error": "unauthorized"}));
                    break;
                }
                if !msg.as_object().is_some_and(|fields| fields.keys().all(|key| {
                    matches!(key.as_str(), "type" | "name" | "token" | "server_token")
                })) || msg.get("token").is_some_and(|v| !v.is_string()) {
                    if !reply(&tx, json!({"type": "error", "error": "invalid registration"})) {
                        break;
                    }
                    continue;
                }
                let Some(req_name) = msg.get("name").and_then(Value::as_str).filter(|s| valid_name(s)) else {
                    if !reply(&tx, json!({"type": "error", "error": "invalid name"})) {
                        break;
                    }
                    continue;
                };
                let req_name = req_name.to_string();
                let req_token = msg.get("token").and_then(Value::as_str);
                let outcome = {
                    let mut registry = state.registry.lock().unwrap();
                    registry.tokens.retain(|_, record| record.expires.is_none_or(|until| until > Instant::now()));
                    let valid = req_token.is_some_and(|t| registry.tokens.get(&req_name).is_some_and(|record| {
                        record.value.as_bytes().ct_eq(t.as_bytes()).into()
                    }));
                    if registry.tokens.contains_key(&req_name) && !valid {
                        None
                    } else {
                        if !registry.tokens.contains_key(&req_name) && registry.tokens.len() == MAX_TOKENS {
                            // ponytail: bounded linear eviction; index only if token churn matters.
                            if let Some(oldest) = registry.tokens.iter()
                                .filter_map(|(name, record)| record.expires.map(|until| (name.clone(), until)))
                                .min_by_key(|(_, until)| *until).map(|(name, _)| name) {
                                registry.tokens.remove(&oldest);
                            }
                        }
                        let tok = token();
                        registry.tokens.insert(req_name.clone(), TokenRecord { value: tok.clone(), expires: None });
                        if let Some(old) = registry.users.insert(req_name.clone(), Session {
                            tx: tx.clone(), shutdown: shutdown_tx.clone(),
                        }) {
                            let _ = old.shutdown.send(true);
                        }
                        let queued = reply(&tx, json!({"type": "welcome", "user": req_name, "token": tok}));
                        if queued {
                            broadcast(&registry, Arc::new(json!({"type": "joined", "user": req_name}).to_string()));
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
                let to = msg.get("to").and_then(Value::as_str);
                let all = msg.get("broadcast") == Some(&Value::Bool(true));
                let valid = msg.as_object().is_some_and(|fields| fields.keys().all(|key| {
                    matches!(key.as_str(), "type" | "payload" | "to" | "broadcast")
                }) && fields.contains_key("payload"))
                    && msg.get("broadcast").is_none_or(Value::is_boolean)
                    && msg.get("to").is_none_or(Value::is_string)
                    && (all != to.is_some()) && to.is_none_or(valid_name);
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
                    if !registry.users.get(from).is_some_and(|session| session.tx.same_channel(&tx)) {
                        Some("register first")
                    } else if to.is_some_and(|to| !registry.users.contains_key(to)) {
                        Some("user unavailable")
                    } else {
                        if all {
                            broadcast(&registry, line);
                        } else {
                            deliver(&registry.users[from], line.clone());
                            if let Some(recipient) = to.filter(|recipient| *recipient != from) {
                                deliver(&registry.users[recipient], line);
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
                let active = name.as_deref().is_some_and(|name| registry.users.get(name)
                    .is_some_and(|session| session.tx.same_channel(&tx)));
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
                if !registry.users.get(name.as_deref().unwrap()).is_some_and(|session| session.tx.same_channel(&tx))
                    || !reply(&tx, json!({"type": "pong"})) {
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
        let owned = registry.users.get(&name).is_some_and(|session| session.tx.same_channel(&tx));
        if owned {
            registry.users.remove(&name);
            if let Some(record) = registry.tokens.get_mut(&name) {
                record.expires = Some(Instant::now() + TOKEN_TTL);
            }
            broadcast(&registry, Arc::new(json!({"type": "left", "user": name}).to_string()));
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
    let auth_token = std::env::var("CHAT_RELAY_AUTH_TOKEN").expect("CHAT_RELAY_AUTH_TOKEN required");
    assert!(auth_token.len() == 64 && auth_token.bytes().all(|b| b.is_ascii_hexdigit()),
        "CHAT_RELAY_AUTH_TOKEN must be 64 hexadecimal characters");
    let addr = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("CHAT_RELAY_ADDR").ok())
        .unwrap_or_else(|| "127.0.0.1:9000".to_string());
    let addr: SocketAddr = addr.parse().expect("CHAT_RELAY_ADDR must be IP:port");
    let tls = match (std::env::var("CHAT_RELAY_TLS_CERT"), std::env::var("CHAT_RELAY_TLS_KEY")) {
        (Ok(cert), Ok(key)) => Some(tls_acceptor(&cert, &key).expect("load TLS certificate and key")),
        (Err(std::env::VarError::NotPresent), Err(std::env::VarError::NotPresent)) if addr.ip().is_loopback() => None,
        _ => panic!("TLS certificate and key required for non-loopback bind"),
    };
    let listener = TcpListener::bind(addr).await.expect("bind");
    println!("chat-relay listening on {addr}");
    let state = Arc::new(State { registry: Mutex::new(Registry::default()), auth_token });
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (sock, peer) = listener.accept().await.expect("accept");
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
                ("slow".into(), Session { tx: slow_tx, shutdown: slow_shutdown }),
                ("fast".into(), Session { tx: fast_tx, shutdown: fast_shutdown }),
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
