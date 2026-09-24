//! chat-relay: encrypted-payload relay server.
//!
//! Raw TCP + NDJSON. The server treats every payload as an opaque blob:
//! it never sees (or logs) plaintext. Routing is a flat fan-out to all
//! registered users; filtering logic lives in the clients.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, LinesCodec};

/// Max size of a single line (message envelope), 16 MiB.
const MAX_LINE: usize = 16 * 1024 * 1024;
/// Outbound queue depth per connection.
const TX_BUFFER: usize = 256;

#[derive(Default)]
struct State {
    /// name -> outbound queue of the live connection
    users: Mutex<HashMap<String, mpsc::Sender<String>>>,
    /// token -> name (lets a client reclaim its name after reconnect)
    tokens: Mutex<HashMap<String, String>>,
}

fn token() -> String {
    // 128 random bits is plenty for a session handle.
    format!("{:032x}", rand::random::<u128>())
}

/// Fan a line out to every registered user, including the sender.
/// Dead queues are simply skipped; the owning task cleans itself up.
async fn broadcast(state: &State, line: String) {
    let txs: Vec<mpsc::Sender<String>> = {
        let users = state.users.lock().unwrap();
        users.values().cloned().collect()
    };
    for tx in txs {
        let _ = tx.send(line.clone()).await;
    }
}

async fn handle(sock: TcpStream, state: Arc<State>) {
    let peer = sock.peer_addr().map(|a| a.to_string()).unwrap_or_default();
    let (rd, wr) = sock.into_split();
    let mut reader = FramedRead::new(rd, LinesCodec::new_with_max_length(MAX_LINE));
    let mut writer = BufWriter::new(wr);
    let (tx, mut rx) = mpsc::channel::<String>(TX_BUFFER);

    let writer_task = tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if writer.write_all(line.as_bytes()).await.is_err()
                || writer.write_all(b"\n").await.is_err()
                || writer.flush().await.is_err()
            {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });

    let mut name: Option<String> = None;
    while let Some(Ok(line)) = reader.next().await {
        let msg = match serde_json::from_str::<Value>(&line) {
            Ok(v) => v,
            Err(_) => {
                let _ = tx.send(json!({"type": "error", "error": "bad json"}).to_string()).await;
                continue;
            }
        };
        match msg.get("type").and_then(Value::as_str) {
            Some("register") => {
                let req_name = msg
                    .get("name")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                let Some(req_name) = req_name else {
                    let _ = tx.send(json!({"type": "error", "error": "missing name"}).to_string()).await;
                    continue;
                };
                let req_token = msg.get("token").and_then(Value::as_str).map(str::to_string);
                // All lock work happens inside this block; no await under a guard.
                let outcome = {
                    let users = state.users.lock().unwrap();
                    let mut tokens = state.tokens.lock().unwrap();
                    let valid = req_token
                        .as_deref()
                        .is_some_and(|t| tokens.get(t) == Some(&req_name));
                    if users.contains_key(&req_name) && !valid {
                        None
                    } else {
                        let tok = match req_token {
                            Some(t) if valid => t,
                            _ => {
                                let t = token();
                                tokens.insert(t.clone(), req_name.clone());
                                t
                            }
                        };
                        Some(tok)
                    }
                };
                let Some(tok) = outcome else {
                    let _ = tx
                        .send(json!({"type": "error", "error": "name taken"}).to_string())
                        .await;
                    continue;
                };
                state.users.lock().unwrap().insert(req_name.clone(), tx.clone());
                name = Some(req_name.clone());
                println!("{peer} registered as {req_name}");
                let _ = tx
                    .send(json!({"type": "welcome", "user": req_name, "token": tok}).to_string())
                    .await;
                // Everyone (the new user included) learns about the join.
                broadcast(
                    &state,
                    json!({"type": "joined", "user": req_name}).to_string(),
                )
                .await;
            }
            Some("msg") => {
                let Some(from) = name.clone() else {
                    let _ = tx
                        .send(json!({"type": "error", "error": "register first"}).to_string())
                        .await;
                    continue;
                };
                // Stamp the sender, keep everything else the client wrote
                // (payload, kind, msg_id, ...) untouched, and relay as-is.
                let mut out = msg;
                out["from"] = json!(from);
                broadcast(&state, out.to_string()).await;
            }
            Some("users") => {
                if name.is_none() {
                    let _ = tx
                        .send(json!({"type": "error", "error": "register first"}).to_string())
                        .await;
                    continue;
                }
                let users: Vec<String> = state.users.lock().unwrap().keys().cloned().collect();
                // Reply goes to the requester only, not a broadcast.
                let _ = tx
                    .send(json!({"type": "users", "users": users}).to_string())
                    .await;
            }
            _ => {
                let _ = tx
                    .send(json!({"type": "error", "error": "unknown type"}).to_string())
                    .await;
            }
        }
    }

    if let Some(name) = name.take() {
        let removed = {
            let mut users = state.users.lock().unwrap();
            // Only remove our own entry; a token-reclaim may have replaced it.
            let owned = users.get(&name).is_some_and(|t| t.same_channel(&tx));
            if owned {
                users.remove(&name);
            }
            owned
        };
        if removed {
            println!("{peer} disconnected: {name}");
            broadcast(&state, json!({"type": "left", "user": name}).to_string()).await;
        }
    }
    // Dropping tx lets the writer task drain and exit.
    drop(tx);
    let _ = writer_task.await;
}

#[tokio::main]
async fn main() {
    let addr = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("CHAT_RELAY_ADDR").ok())
        .unwrap_or_else(|| "0.0.0.0:9000".to_string());
    let listener = TcpListener::bind(&addr).await.expect("bind");
    println!("chat-relay listening on {addr}");
    let state = Arc::new(State::default());
    loop {
        let (sock, _) = listener.accept().await.expect("accept");
        let state = state.clone();
        tokio::spawn(handle(sock, state));
    }
}
