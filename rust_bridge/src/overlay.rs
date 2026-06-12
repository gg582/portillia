use std::ffi::{c_char, c_int, CStr, CString};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::IntoRawFd;
use std::ptr;
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{bail, Context};
use base64::{engine::general_purpose::STANDARD as BASE64_STD, Engine};
use futures_util::future::poll_fn;
use futures_util::TryStreamExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, Mutex};
use tokio::time;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use wireguard_control::{
    AllowedIp as WgAllowedIp, Backend as WgBackend, Device as WgDevice,
    DeviceUpdate as WgDeviceUpdate, InterfaceName as WgInterfaceName, Key as WgKey,
    PeerConfigBuilder,
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use yamux::{Config as YamuxConfig, Connection as YamuxConnection, Mode};

// ---------- FFI helpers ----------

fn to_rust_string(c_str: *const c_char) -> Option<String> {
    if c_str.is_null() { return None; }
    unsafe { CStr::from_ptr(c_str).to_str().ok().map(|s| s.to_string()) }
}

fn cstring_or_null(s: String) -> *mut c_char {
    CString::new(s).map(|c| c.into_raw()).unwrap_or(ptr::null_mut())
}

extern "C" {
    fn portillia_crypto_derive_overlay_ipv4(pubkey_b64: *const c_char, out_ipv4: *mut c_char) -> c_int;
}

fn derive_overlay_ipv4(pubkey_b64: &str) -> Option<Ipv4Addr> {
    let c_pubkey = CString::new(pubkey_b64).ok()?;
    // C function writes into the buffer; allocate a large enough buffer.
    let out_buf = vec![0u8; 32];
    let c_out = unsafe { CString::from_vec_unchecked(out_buf) };
    let c_out_ptr = c_out.into_raw();
    let rc = unsafe { portillia_crypto_derive_overlay_ipv4(c_pubkey.as_ptr(), c_out_ptr) };
    let c_out = unsafe { CString::from_raw(c_out_ptr) };
    if rc != 0 {
        return None;
    }
    let s = c_out.to_str().ok()?;
    s.parse().ok()
}

// ---------- WireGuard key helpers ----------

const WG_KEY_LEN: usize = 32;

fn normalize_wireguard_private_key(raw: &str) -> anyhow::Result<[u8; WG_KEY_LEN]> {
    let value = raw.trim();
    if value.is_empty() {
        bail!("wireguard private key is required");
    }
    let decoded = if value.len() == 64 && !value.contains('=') {
        hex::decode(value).context("decode wireguard private key hex")?
    } else {
        BASE64_STD.decode(value).context("decode wireguard private key base64")?
    };
    let mut private: [u8; WG_KEY_LEN] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("wireguard private key must be 32 bytes"))?;
    clamp_wireguard_private_key(&mut private);
    Ok(private)
}

fn clamp_wireguard_private_key(private: &mut [u8; WG_KEY_LEN]) {
    private[0] &= 248;
    private[WG_KEY_LEN - 1] = (private[WG_KEY_LEN - 1] & 127) | 64;
}

fn wireguard_public_key_from_private_bytes(private: [u8; WG_KEY_LEN]) -> String {
    let secret = StaticSecret::from(private);
    let public = X25519PublicKey::from(&secret);
    BASE64_STD.encode(public.as_bytes())
}

fn validate_wireguard_public_key(raw: &str) -> anyhow::Result<()> {
    let decoded = BASE64_STD
        .decode(raw.trim())
        .context("wireguard public key must be base64 encoded")?;
    if decoded.len() != WG_KEY_LEN {
        bail!("wireguard public key must be 32 bytes");
    }
    Ok(())
}

fn wireguard_key(raw: &str) -> anyhow::Result<WgKey> {
    let decoded = BASE64_STD
        .decode(raw.trim())
        .context("wireguard key must be base64 encoded")?;
    let bytes: [u8; WG_KEY_LEN] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("wireguard key must be 32 bytes"))?;
    Ok(WgKey(bytes))
}

// ---------- Overlay config ----------

pub const WIREGUARD_MTU: usize = 1420;
pub const DEFAULT_PEER_YAMUX_PORT: u16 = 7778;
pub const DEFAULT_PERSISTENT_KEEPALIVE_SECS: u16 = 25;
pub const OVERLAY_INTERFACE_NAME: &str = "wg-portal";

#[derive(Debug, Clone)]
struct OverlayConfig {
    private_key_b64: String,
    listen_port: u16,
    overlay_ipv4: Ipv4Addr,
}

impl OverlayConfig {
    fn from_keys(private_key: &str, public_key: &str, listen_port: u16) -> anyhow::Result<Self> {
        if listen_port == 0 {
            bail!("wireguard listen port is invalid");
        }
        let private = normalize_wireguard_private_key(private_key)?;
        let derived_public = wireguard_public_key_from_private_bytes(private);
        let public_key = if public_key.trim().is_empty() {
            derived_public
        } else {
            validate_wireguard_public_key(public_key)?;
            let pk = public_key.trim().to_string();
            if pk != derived_public {
                bail!("identity wireguard public key does not match private key");
            }
            pk
        };
        let overlay_ipv4 = derive_overlay_ipv4(&public_key)
            .context("derive wireguard overlay ipv4")?;
        Ok(Self {
            private_key_b64: BASE64_STD.encode(&private),
            listen_port,
            overlay_ipv4,
        })
    }
}

// ---------- Hop mux ----------

const MAX_HOP_TOKEN_BYTES: usize = 256;
const DEFAULT_TOKEN_TIMEOUT: Duration = Duration::from_secs(2);

pub trait BoxedIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> BoxedIo for T {}

type BoxedIoStream = Box<dyn BoxedIo>;

pub struct HopStream {
    pub stream: Compat<yamux::Stream>,
    pub token: String,
}

pub struct HopMux {
    incoming_tx: mpsc::Sender<HopStream>,
    incoming_rx: Mutex<mpsc::Receiver<HopStream>>,
}

impl HopMux {
    pub fn new() -> Arc<Self> {
        let (incoming_tx, incoming_rx) = mpsc::channel(256);
        Arc::new(Self {
            incoming_tx,
            incoming_rx: Mutex::new(incoming_rx),
        })
    }

    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> anyhow::Result<()> {
        loop {
            let (conn, remote_addr) = listener.accept().await.context("accept hop mux")?;
            let hop_mux = Arc::clone(&self);
            tokio::spawn(async move {
                hop_mux.serve_connection(conn, remote_addr.to_string()).await;
            });
        }
    }

    async fn serve_connection<I>(self: Arc<Self>, conn: I, remote_addr: String)
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let boxed: BoxedIoStream = Box::new(conn);
        let mut session = YamuxConnection::new(boxed.compat(), yamux_config(), Mode::Server);
        loop {
            match poll_fn(|cx| session.poll_next_inbound(cx)).await {
                Some(Ok(stream)) => {
                    let incoming = self.incoming_tx.clone();
                    let remote_addr = remote_addr.clone();
                    tokio::spawn(async move {
                        handle_inbound_stream(stream.compat(), remote_addr, incoming).await;
                    });
                }
                Some(Err(err)) => {
                    eprintln!("hop mux session closed: {err}");
                    return;
                }
                None => {
                    return;
                }
            }
        }
    }

    pub async fn accept(&self) -> Option<HopStream> {
        self.incoming_rx.lock().await.recv().await
    }
}

async fn handle_inbound_stream(
    mut stream: Compat<yamux::Stream>,
    remote_addr: String,
    incoming: mpsc::Sender<HopStream>,
) {
    let token = match time::timeout(DEFAULT_TOKEN_TIMEOUT, read_hop_token_frame(&mut stream)).await {
        Ok(Ok(token)) => token,
        Ok(Err(err)) => {
            eprintln!("hop mux token rejected: {err}");
            let _ = stream.shutdown().await;
            return;
        }
        Err(_) => {
            eprintln!("hop mux token read timed out");
            let _ = stream.shutdown().await;
            return;
        }
    };

    if incoming
        .send(HopStream {
            stream,
            token,
        })
        .await
        .is_err()
    {
        eprintln!("hop mux stream dropped because accept queue is closed");
    }
}

async fn read_hop_token_frame<R>(reader: &mut R) -> anyhow::Result<String>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    reader
        .read_exact(&mut header)
        .await
        .context("read hop token frame length")?;
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 || len > MAX_HOP_TOKEN_BYTES {
        bail!("invalid hop token frame length");
    }
    let mut payload = vec![0u8; len];
    reader
        .read_exact(&mut payload)
        .await
        .context("read hop token frame payload")?;
    let token = String::from_utf8(payload)
        .context("hop token frame payload is not utf8")?
        .trim()
        .to_string();
    if token.is_empty() {
        bail!("next hop token is required");
    }
    Ok(token)
}

async fn write_hop_token_frame<W>(writer: &mut W, token: &str) -> anyhow::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let token = token.trim();
    if token.is_empty() {
        bail!("next hop token is required");
    }
    let payload = token.as_bytes();
    if payload.len() > MAX_HOP_TOKEN_BYTES {
        bail!("next hop token is too large");
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    writer.write_all(&frame).await.context("write hop token frame")?;
    writer.flush().await.context("flush hop token frame")?;
    Ok(())
}

fn yamux_config() -> YamuxConfig {
    let mut config = YamuxConfig::default();
    config.set_split_send_size(1200);
    config.set_max_connection_receive_window(None);
    config
}

async fn drive_yamux_session<I>(mut session: YamuxConnection<I>)
where
    I: futures_util::AsyncRead + futures_util::AsyncWrite + Unpin + Send + 'static,
{
    loop {
        match poll_fn(|cx| session.poll_next_inbound(cx)).await {
            Some(Ok(_stream)) => {
                // Client connections do not expect inbound streams; drop them.
            }
            Some(Err(err)) => {
                eprintln!("yamux client session error: {err}");
                return;
            }
            None => return,
        }
    }
}

// ---------- Overlay runtime ----------

#[derive(Debug, Clone)]
struct OverlayPeer {
    public_key: String,
    endpoint: SocketAddr,
    allowed_ip: Ipv4Addr,
}

struct OverlayRuntime {
    config: OverlayConfig,
    interface_name: WgInterfaceName,
    sync_lock: std::sync::Mutex<()>,
}

impl OverlayRuntime {
    async fn new(config: OverlayConfig) -> anyhow::Result<Self> {
        let private = normalize_wireguard_private_key(&config.private_key_b64)?;
        let interface_name = WgInterfaceName::from_str(OVERLAY_INTERFACE_NAME)
            .map_err(|err| anyhow::anyhow!("invalid wireguard interface name: {err}"))?;

        WgDeviceUpdate::new()
            .set_private_key(WgKey(private))
            .set_listen_port(config.listen_port)
            .replace_peers()
            .apply(&interface_name, WgBackend::Kernel)
            .with_context(|| {
                format!(
                    "configure kernel wireguard interface {OVERLAY_INTERFACE_NAME} on udp port {}",
                    config.listen_port
                )
            })?;

        configure_overlay_link_address(&interface_name, config.overlay_ipv4)
            .await
            .with_context(|| {
                format!(
                    "configure overlay address {} on {OVERLAY_INTERFACE_NAME}",
                    config.overlay_ipv4
                )
            })?;

        Ok(Self {
            config,
            interface_name,
            sync_lock: std::sync::Mutex::new(()),
        })
    }

    async fn sync_peers(&self, peers: &[OverlayPeer]) -> anyhow::Result<()> {
        let _guard = self.sync_lock.lock().map_err(|_| anyhow::anyhow!("wireguard sync lock poisoned"))?;
        let mut update = WgDeviceUpdate::new();
        for peer in peers {
            let public = wireguard_key(&peer.public_key)?;
            let allowed = WgAllowedIp {
                address: IpAddr::V4(peer.allowed_ip),
                cidr: 32,
            };
            let builder = PeerConfigBuilder::new(&public)
                .set_endpoint(peer.endpoint)
                .add_allowed_ip(allowed.address, allowed.cidr)
                .set_persistent_keepalive_interval(DEFAULT_PERSISTENT_KEEPALIVE_SECS);
            update = update.add_peer(builder);
        }
        update.apply(&self.interface_name, WgBackend::Kernel)?;
        Ok(())
    }
}

impl Drop for OverlayRuntime {
    fn drop(&mut self) {
        let _ = WgDevice::get(&self.interface_name, WgBackend::Kernel).and_then(|d| d.delete());
    }
}

async fn configure_overlay_link_address(
    interface_name: &WgInterfaceName,
    overlay_ipv4: Ipv4Addr,
) -> anyhow::Result<()> {
    let (connection, handle, _) = rtnetlink::new_connection().context("open netlink connection")?;
    tokio::spawn(connection);

    let name = interface_name.as_str_lossy().to_string();
    let mut links = handle.link().get().match_name(name.clone()).execute();
    let link = links
        .try_next()
        .await
        .with_context(|| format!("look up wg link {name}"))?
        .with_context(|| format!("wg link {name} not present after wireguard-control apply"))?;
    let link_index = link.header.index;

    let mut existing = handle
        .address()
        .get()
        .set_link_index_filter(link_index)
        .execute();
    while let Some(addr) = existing
        .try_next()
        .await
        .with_context(|| format!("enumerate existing addresses on {name}"))?
    {
        handle
            .address()
            .del(addr)
            .execute()
            .await
            .with_context(|| format!("remove stale address on {name}"))?;
    }

    handle
        .address()
        .add(link_index, IpAddr::V4(overlay_ipv4), 10)
        .execute()
        .await
        .with_context(|| format!("add overlay address {overlay_ipv4}/10 on {name}"))?;

    handle
        .link()
        .set(
            rtnetlink::LinkUnspec::new_with_index(link_index)
                .mtu(WIREGUARD_MTU as u32)
                .up()
                .build(),
        )
        .execute()
        .await
        .with_context(|| format!("set link up + mtu on {name}"))?;

    Ok(())
}

// ---------- Global state ----------

static RUNTIME: OnceLock<Result<Runtime, String>> = OnceLock::new();
static OVERLAY: OnceLock<Arc<OverlayRuntime>> = OnceLock::new();
static HOP_MUX: OnceLock<Arc<HopMux>> = OnceLock::new();

fn init_runtime() -> anyhow::Result<&'static Runtime> {
    RUNTIME
        .get_or_init(|| Runtime::new().map_err(|e| e.to_string()))
        .as_ref()
        .map_err(|e| anyhow::anyhow!("{e}"))
}

// ---------- Bridge a tokio stream to a Unix FD ----------

fn bridge_stream_to_fd<S>(stream: S) -> anyhow::Result<std::os::fd::RawFd>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (local, peer) = std::os::unix::net::UnixStream::pair().context("create unix socketpair")?;
    let raw_fd = peer.into_raw_fd();
    local.set_nonblocking(true).context("set nonblocking")?;
    let mut local = tokio::net::UnixStream::from_std(local).context("wrap unix stream")?;

    tokio::spawn(async move {
        let (mut local_read, mut local_write) = local.split();
        let (mut stream_read, mut stream_write) = tokio::io::split(stream);
        let a = tokio::io::copy(&mut local_read, &mut stream_write);
        let b = tokio::io::copy(&mut stream_read, &mut local_write);
        let _ = tokio::join!(a, b);
    });

    Ok(raw_fd)
}

// ---------- FFI exports ----------

#[no_mangle]
pub extern "C" fn OverlayInit(c_private_key: *const c_char, c_public_key: *const c_char, c_listen_port: c_int) -> c_int {
    let private_key = match to_rust_string(c_private_key) {
        Some(s) => s,
        None => return -1,
    };
    let public_key = to_rust_string(c_public_key).unwrap_or_default();
    let listen_port = c_listen_port as u16;

    let config = match OverlayConfig::from_keys(&private_key, &public_key, listen_port) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("OverlayInit config failed: {err}");
            return -1;
        }
    };

    let runtime = match init_runtime() {
        Ok(r) => r,
        Err(err) => {
            eprintln!("OverlayInit runtime failed: {err}");
            return -1;
        }
    };

    let overlay = match runtime.block_on(OverlayRuntime::new(config)) {
        Ok(o) => Arc::new(o),
        Err(err) => {
            eprintln!("OverlayInit wireguard failed: {err}");
            return -1;
        }
    };

    let hop_mux = HopMux::new();
    let listen_addr = SocketAddr::new(IpAddr::V4(overlay.config.overlay_ipv4), DEFAULT_PEER_YAMUX_PORT);
    let listener = match runtime.block_on(TcpListener::bind(listen_addr)) {
        Ok(l) => l,
        Err(err) => {
            eprintln!("OverlayInit bind failed: {err}");
            return -1;
        }
    };

    runtime.spawn({
        let hop_mux = Arc::clone(&hop_mux);
        async move {
            let _ = hop_mux.serve(listener).await;
        }
    });

    if OVERLAY.set(overlay).is_err() {
        eprintln!("OverlayInit already initialized");
        return -1;
    }
    if HOP_MUX.set(hop_mux).is_err() {
        eprintln!("OverlayInit hop mux already initialized");
        return -1;
    }

    0
}

#[derive(Debug, serde::Deserialize)]
struct RelayDescriptorInput {
    #[serde(default)]
    wireguard_public_key: String,
    #[serde(default, rename = "wireguard_port")]
    wireguard_port: i32,
    #[serde(default, rename = "api_https_addr")]
    api_https_addr: String,
}

#[no_mangle]
pub extern "C" fn OverlaySyncJSON(c_relays_json: *const c_char) -> c_int {
    let json = match to_rust_string(c_relays_json) {
        Some(s) => s,
        None => return -1,
    };

    let overlay = match OVERLAY.get() {
        Some(o) => o,
        None => return -1,
    };
    let runtime = match init_runtime() {
        Ok(r) => r,
        Err(err) => {
            eprintln!("OverlaySyncJSON runtime failed: {err}");
            return -1;
        }
    };

    let descriptors: Vec<RelayDescriptorInput> = match parse_relays_json(&json) {
        Ok(d) => d,
        Err(err) => {
            eprintln!("OverlaySyncJSON parse failed: {err}");
            return -1;
        }
    };

    let mut peers = Vec::new();
    for desc in descriptors {
        if desc.wireguard_public_key.is_empty() || desc.wireguard_port <= 0 || desc.wireguard_port > 65535 {
            continue;
        }
        if let Ok(peer) = overlay_peer_from_descriptor(&desc) {
            peers.push(peer);
        }
    }

    match runtime.block_on(overlay.sync_peers(&peers)) {
        Ok(_) => 0,
        Err(err) => {
            eprintln!("OverlaySyncJSON failed: {err}");
            -1
        }
    }
}

fn parse_relays_json(json: &str) -> anyhow::Result<Vec<RelayDescriptorInput>> {
    let wrapped: serde_json::Value = serde_json::from_str(json).context("invalid json")?;
    if let Some(arr) = wrapped
        .get("relays")
        .or_else(|| wrapped.get("data").and_then(|d| d.get("relays")))
    {
        return unwrap_descriptor_array(arr.clone());
    }
    if let Some(arr) = wrapped.as_array() {
        return unwrap_descriptor_array(serde_json::Value::Array(arr.clone()));
    }
    bail!("expected top-level array or object with relays/data.relays")
}

fn unwrap_descriptor_array(value: serde_json::Value) -> anyhow::Result<Vec<RelayDescriptorInput>> {
    let arr = value.as_array().context("relays is not an array")?;
    arr.iter()
        .map(|v| {
            let inner = v.get("Descriptor").unwrap_or(v);
            serde_json::from_value(inner.clone()).context("parse relay descriptor")
        })
        .collect::<Result<Vec<_>, _>>()
}

fn overlay_peer_from_descriptor(desc: &RelayDescriptorInput) -> anyhow::Result<OverlayPeer> {
    validate_wireguard_public_key(&desc.wireguard_public_key)?;
    let endpoint = relay_wireguard_endpoint(desc)?;
    let allowed_ip = derive_overlay_ipv4(&desc.wireguard_public_key)
        .context("derive peer overlay ipv4")?;
    Ok(OverlayPeer {
        public_key: desc.wireguard_public_key.clone(),
        endpoint,
        allowed_ip,
    })
}

fn relay_wireguard_endpoint(desc: &RelayDescriptorInput) -> anyhow::Result<SocketAddr> {
    let url = url::Url::parse(desc.api_https_addr.trim())
        .with_context(|| format!("parse relay url {:?}", desc.api_https_addr))?;
    let host = url
        .host_str()
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .context("api_https_addr host is required")?;
    let endpoint_str = join_host_port(host, desc.wireguard_port as u16);
    endpoint_str.parse().context("parse wireguard endpoint")
}

fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[no_mangle]
pub extern "C" fn HopMuxOpenStreamFD(c_overlay_ipv4: *const c_char, c_token: *const c_char) -> c_int {
    let overlay_ipv4 = match to_rust_string(c_overlay_ipv4) {
        Some(s) => s,
        None => return -1,
    };
    let token = match to_rust_string(c_token) {
        Some(s) => s,
        None => return -1,
    };

    let runtime = match init_runtime() {
        Ok(r) => r,
        Err(err) => {
            eprintln!("HopMuxOpenStreamFD runtime failed: {err}");
            return -1;
        }
    };

    let overlay_ipv4 = overlay_ipv4.trim();
    let ip: IpAddr = match overlay_ipv4.parse() {
        Ok(ip) => ip,
        Err(_) => return -1,
    };
    let addr = SocketAddr::new(ip, DEFAULT_PEER_YAMUX_PORT);

    let fd = match runtime.block_on(async {
        let conn = TcpStream::connect(addr).await
            .with_context(|| format!("connect hop mux peer at {addr}"))?;
        let boxed: BoxedIoStream = Box::new(conn);
        let mut session = YamuxConnection::new(boxed.compat(), yamux_config(), Mode::Client);
        let mut stream = poll_fn(|cx| session.poll_new_outbound(cx))
            .await
            .context("open hop mux stream")?
            .compat();
        write_hop_token_frame(&mut stream, &token).await
            .context("write hop mux token frame")?;
        // Drive the yamux connection in the background so the stream stays alive.
        tokio::spawn(drive_yamux_session(session));
        bridge_stream_to_fd(stream)
    }) {
        Ok(fd) => fd,
        Err(err) => {
            eprintln!("HopMuxOpenStreamFD failed: {err}");
            return -1;
        }
    };

    fd as c_int
}

#[no_mangle]
pub extern "C" fn HopMuxAcceptFD(c_token_out: *mut *mut c_char) -> c_int {
    if c_token_out.is_null() {
        return -1;
    }

    let runtime = match init_runtime() {
        Ok(r) => r,
        Err(err) => {
            eprintln!("HopMuxAcceptFD runtime failed: {err}");
            return -1;
        }
    };
    let hop_mux = match HOP_MUX.get() {
        Some(h) => h,
        None => return -1,
    };

    let hop_stream = match runtime.block_on(hop_mux.accept()) {
        Some(s) => s,
        None => return -1,
    };

    let token = hop_stream.token;
    let fd = match bridge_stream_to_fd(hop_stream.stream) {
        Ok(fd) => fd,
        Err(err) => {
            eprintln!("HopMuxAcceptFD bridge failed: {err}");
            return -1;
        }
    };

    unsafe { *c_token_out = cstring_or_null(token); }
    fd as c_int
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_wrapped_descriptor_array() {
        let json = r#"[{"Descriptor":{"api_https_addr":"https://relay.example.com","wireguard_public_key":"kT4h0mG4lOg0+TI9Z2M6r1hL49n1r6e9Ykv4D7jJnlM=","wireguard_port":51820}}]"#;
        let descs = parse_relays_json(json).expect("parse wrapped");
        assert_eq!(descs.len(), 1);
        assert_eq!(descs[0].wireguard_public_key, "kT4h0mG4lOg0+TI9Z2M6r1hL49n1r6e9Ykv4D7jJnlM=");
        assert_eq!(descs[0].wireguard_port, 51820);
    }

    #[test]
    fn parse_flat_descriptor_array() {
        let json = r#"[{"api_https_addr":"https://relay.example.com","wireguard_public_key":"kT4h0mG4lOg0+TI9Z2M6r1hL49n1r6e9Ykv4D7jJnlM=","wireguard_port":51820}]"#;
        let descs = parse_relays_json(json).expect("parse flat");
        assert_eq!(descs.len(), 1);
    }

    #[test]
    fn parse_relays_object() {
        let json = r#"{"relays":[{"Descriptor":{"api_https_addr":"https://relay.example.com","wireguard_public_key":"kT4h0mG4lOg0+TI9Z2M6r1hL49n1r6e9Ykv4D7jJnlM=","wireguard_port":51820}}]}"#;
        let descs = parse_relays_json(json).expect("parse object");
        assert_eq!(descs.len(), 1);
    }
}
