use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};
use tidemark_core::rpc;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Error as WsError, Message, WebSocket};

type Socket = WebSocket<MaybeTlsStream<TcpStream>>;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const BACKOFF_START: Duration = Duration::from_secs(5);
const BACKOFF_MAX: Duration = Duration::from_secs(300);

pub fn derive_url(rpc_url: &str) -> Result<String> {
    let (scheme, rest) = if let Some(r) = rpc_url.strip_prefix("https://") {
        ("wss", r)
    } else if let Some(r) = rpc_url.strip_prefix("http://") {
        ("ws", r)
    } else {
        bail!("cannot derive a websocket URL from {rpc_url}; pass --ws");
    };
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let authority = match authority.rsplit_once(':') {
        Some((host, "8899")) if host == "localhost" || host == "127.0.0.1" => {
            format!("{host}:8900")
        }
        _ => authority.to_string(),
    };
    Ok(format!("{scheme}://{authority}{tail}"))
}

fn host_port(url: &str) -> Result<(String, u16)> {
    let (default, rest) = if let Some(r) = url.strip_prefix("wss://") {
        (443, r)
    } else if let Some(r) = url.strip_prefix("ws://") {
        (80, r)
    } else {
        bail!("websocket URL must start with ws:// or wss://");
    };
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..end];
    match authority.rsplit_once(':') {
        Some((h, p)) => Ok((h.to_string(), p.parse().context("invalid websocket port")?)),
        None => Ok((authority.to_string(), default)),
    }
}

pub fn subscribe_request(programdata: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "accountSubscribe",
        "params": [programdata, {"encoding": "base64", "commitment": "finalized"}]
    })
    .to_string()
}

pub enum Incoming {
    Subscribed,
    Changed,
    Failed(String),
    Other,
}

pub fn classify(text: &str) -> Incoming {
    let Ok(v) = serde_json::from_str::<Value>(text) else {
        return Incoming::Other;
    };
    if v["method"] == "accountNotification" {
        return Incoming::Changed;
    }
    if let Some(e) = v.get("error") {
        return Incoming::Failed(e.to_string());
    }
    match (v["id"] == 1, v["result"].as_u64()) {
        (true, Some(_)) => Incoming::Subscribed,
        _ => Incoming::Other,
    }
}

fn tcp(socket: &Socket) -> Option<&TcpStream> {
    match socket.get_ref() {
        MaybeTlsStream::Plain(s) => Some(s),
        MaybeTlsStream::Rustls(s) => Some(s.get_ref()),
        _ => None,
    }
}

fn set_timeout(socket: &Socket, d: Duration) {
    if let Some(s) = tcp(socket) {
        let _ = s.set_read_timeout(Some(d.max(Duration::from_millis(1))));
    }
}

fn open(url: &str, programdata: &str) -> Result<Socket> {
    let (host, port) = host_port(url)?;
    let addr = (host.as_str(), port)
        .to_socket_addrs()?
        .next()
        .context("websocket host did not resolve")?;
    let stream = TcpStream::connect_timeout(&addr, HANDSHAKE_TIMEOUT)?;
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let (mut socket, _) = tungstenite::client_tls(url, stream)
        .map_err(|e| anyhow::anyhow!("websocket handshake failed: {e}"))?;
    socket.send(Message::text(subscribe_request(programdata)))?;
    loop {
        if let Message::Text(t) = socket.read()? {
            match classify(&t) {
                Incoming::Subscribed => return Ok(socket),
                Incoming::Failed(e) => bail!("subscription rejected: {e}"),
                _ => {}
            }
        }
    }
}

pub struct Watcher {
    url: String,
    program: String,
    rpc: String,
    socket: Option<Socket>,
    programdata: Option<String>,
    retry_at: Instant,
    backoff: Duration,
}

impl Watcher {
    pub fn new(url: String, rpc: String, program: String) -> Self {
        Watcher {
            url,
            program,
            rpc,
            socket: None,
            programdata: None,
            retry_at: Instant::now(),
            backoff: BACKOFF_START,
        }
    }

    fn connect(&mut self) -> Result<()> {
        if self.programdata.is_none() {
            self.programdata = Some(rpc::programdata_address(&self.rpc, &self.program)?);
        }
        let pd = self.programdata.as_deref().unwrap_or_default();
        self.socket = Some(open(&self.url, pd)?);
        Ok(())
    }

    fn fail(&mut self, e: &dyn std::fmt::Display) {
        self.socket = None;
        eprintln!(
            "{}: websocket: {e}; polling, retrying in {}s",
            self.program,
            self.backoff.as_secs()
        );
        self.retry_at = Instant::now() + self.backoff;
        self.backoff = (self.backoff * 2).min(BACKOFF_MAX);
    }

    pub fn wait(&mut self, interval: Duration) {
        let deadline = Instant::now() + interval;
        if self.socket.is_none() && Instant::now() >= self.retry_at {
            match self.connect() {
                Ok(()) => {
                    self.backoff = BACKOFF_START;
                    println!("{}: subscribed over websocket", self.program);
                }
                Err(e) => self.fail(&format_args!("{e:#}")),
            }
        }
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let Some(socket) = self.socket.as_mut() else {
                std::thread::sleep(left);
                return;
            };
            if left.is_zero() {
                return;
            }
            set_timeout(socket, left);
            match socket.read() {
                Ok(Message::Text(t)) => {
                    if matches!(classify(&t), Incoming::Changed) {
                        return;
                    }
                }
                Ok(_) => {}
                Err(WsError::Io(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => {
                    self.fail(&e);
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_from_rpc_url() {
        assert_eq!(
            derive_url("https://api.devnet.solana.com").unwrap(),
            "wss://api.devnet.solana.com"
        );
        assert_eq!(
            derive_url("https://rpc.example.com/v1?key=abc").unwrap(),
            "wss://rpc.example.com/v1?key=abc"
        );
        assert_eq!(
            derive_url("http://127.0.0.1:8899").unwrap(),
            "ws://127.0.0.1:8900"
        );
        assert_eq!(
            derive_url("http://localhost:8899/").unwrap(),
            "ws://localhost:8900/"
        );
        assert_eq!(
            derive_url("http://node.internal:8899").unwrap(),
            "ws://node.internal:8899"
        );
        assert!(derive_url("ftp://x").is_err());
    }

    #[test]
    fn splits_host_and_port() {
        assert_eq!(
            host_port("wss://api.devnet.solana.com/x").unwrap(),
            ("api.devnet.solana.com".to_string(), 443)
        );
        assert_eq!(
            host_port("ws://localhost:8900").unwrap(),
            ("localhost".to_string(), 8900)
        );
        assert!(host_port("http://x").is_err());
    }

    #[test]
    fn builds_subscription() {
        let v: Value = serde_json::from_str(&subscribe_request("PD1")).unwrap();
        assert_eq!(v["method"], "accountSubscribe");
        assert_eq!(v["params"][0], "PD1");
        assert_eq!(v["params"][1]["encoding"], "base64");
        assert_eq!(v["params"][1]["commitment"], "finalized");
    }

    #[test]
    fn classifies_messages() {
        assert!(matches!(
            classify(r#"{"jsonrpc":"2.0","result":23784,"id":1}"#),
            Incoming::Subscribed
        ));
        assert!(matches!(
            classify(
                r#"{"jsonrpc":"2.0","method":"accountNotification","params":{"result":{"context":{"slot":5},"value":{}},"subscription":23784}}"#
            ),
            Incoming::Changed
        ));
        assert!(matches!(
            classify(r#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"bad"},"id":1}"#),
            Incoming::Failed(_)
        ));
        assert!(matches!(classify("not json"), Incoming::Other));
    }
}
