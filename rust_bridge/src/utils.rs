use std::ffi::{c_char, CStr, CString};
use std::ptr;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use base64::Engine;
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use reqwest::blocking::Client;
use url::Url;

fn to_rust_string(c_str: *const c_char) -> Option<String> {
    if c_str.is_null() { return None; }
    unsafe { CStr::from_ptr(c_str).to_str().ok().map(|s| s.to_string()) }
}

fn cstring_or_null(s: String) -> *mut c_char {
    CString::new(s).map(|c| c.into_raw()).unwrap_or(ptr::null_mut())
}

fn json_or_null<T: Serialize>(v: &T) -> *mut c_char {
    match serde_json::to_string(v) {
        Ok(j) => cstring_or_null(j),
        Err(_) => ptr::null_mut(),
    }
}

// ---------- Identity helpers ----------

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Identity {
    #[serde(default)]
    name: String,
    #[serde(default)]
    address: String,
    #[serde(skip)]
    token_secret: String,
}

impl Identity {
    fn key(&self) -> String {
        let name = self.name.trim().to_lowercase();
        let addr = self.address.trim().to_lowercase();
        if name.is_empty() && addr.is_empty() { return String::new(); }
        format!("{}:{}", name, addr)
    }
}

fn derive_token(identity: &Identity, parts: &[&str]) -> Option<String> {
    let secret = identity.token_secret.trim();
    if secret.is_empty() { return None; }
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(b"Portal identity token v1\n");
    mac.update(identity.key().as_bytes());
    for part in parts {
        mac.update(b"\n");
        mac.update(part.len().to_string().as_bytes());
        mac.update(b":");
        mac.update(part.trim().as_bytes());
    }
    let result = mac.finalize();
    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(result.into_bytes()))
}

// ---------- Hostname / DNS utils ----------

fn hostname_hash(hostname: &str) -> String {
    let h = hostname.trim().to_lowercase();
    let mut hasher = Sha256::new();
    hasher.update(h.as_bytes());
    let sum = hasher.finalize();
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &sum)
}

fn portal_root_host(relay_url: &str) -> Option<String> {
    let url = Url::parse(relay_url).ok()?;
    let host = url.host_str()?;
    let host_lc = host.to_lowercase();
    let parts: Vec<&str> = host_lc.split('.').collect();
    if parts.len() >= 2 {
        let root = parts[parts.len() - 2..].join(".");
        Some(root)
    } else {
        Some(host_lc)
    }
}

fn lease_hostname(name: &str, root_host: &str) -> Option<String> {
    let label = normalize_dns_label(name)?;
    let root = normalize_dns_label(root_host)?;
    Some(format!("{}.{}", label, root))
}

fn normalize_dns_label(label: &str) -> Option<String> {
    let mut out = String::new();
    for ch in label.trim().to_lowercase().chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' {
            out.push(ch);
        } else if ch == '_' || ch == '.' || ch == ' ' {
            if !out.ends_with('-') { out.push('-'); }
        }
    }
    out = out.trim_matches('-').to_string();
    if out.is_empty() || out.len() > 63 { return None; }
    if out.starts_with('-') || out.ends_with('-') { return None; }
    Some(out)
}

// ---------- Discovery HTTP helpers ----------

use std::sync::OnceLock;
static DISCOVERY_CLIENT: OnceLock<Client> = OnceLock::new();
fn get_discovery_client() -> &'static Client {
    DISCOVERY_CLIENT.get_or_init(|| {
        Client::builder()
            .timeout(Duration::from_secs(8))
            .build()
            .expect("build discovery client")
    })
}

#[no_mangle]
pub extern "C" fn DiscoveryPollJSON(c_url: *const c_char) -> *mut c_char {
    let url = match to_rust_string(c_url) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    match get_discovery_client().get(&url).send() {
        Ok(resp) => {
            if resp.status().as_u16() >= 400 { return ptr::null_mut(); }
            match resp.text() {
                Ok(body) => cstring_or_null(body),
                Err(_) => ptr::null_mut(),
            }
        }
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn DiscoveryAnnounceJSON(c_url: *const c_char, c_descriptor_json: *const c_char) -> *mut c_char {
    let url = match to_rust_string(c_url) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    let body = match to_rust_string(c_descriptor_json) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    match get_discovery_client().post(&url).header("Content-Type", "application/json").body(body).send() {
        Ok(resp) => {
            if resp.status().as_u16() >= 400 { return ptr::null_mut(); }
            match resp.text() {
                Ok(text) => cstring_or_null(text),
                Err(_) => ptr::null_mut(),
            }
        }
        Err(_) => ptr::null_mut(),
    }
}

// ---------- Compatibility helpers (100% Go parity) ----------

#[no_mangle]
pub extern "C" fn HostnameHashJSON(c_hostname: *const c_char) -> *mut c_char {
    let hostname = match to_rust_string(c_hostname) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    cstring_or_null(hostname_hash(&hostname))
}

#[no_mangle]
pub extern "C" fn DeriveTokenJSON(c_identity_json: *const c_char, c_parts_json: *const c_char) -> *mut c_char {
    let identity: Identity = match to_rust_string(c_identity_json) {
        Some(s) => match serde_json::from_str(&s) {
            Ok(i) => i,
            Err(_) => return ptr::null_mut(),
        },
        None => return ptr::null_mut(),
    };
    let parts: Vec<String> = match to_rust_string(c_parts_json) {
        Some(s) => match serde_json::from_str(&s) {
            Ok(p) => p,
            Err(_) => return ptr::null_mut(),
        },
        None => return ptr::null_mut(),
    };
    let parts_ref: Vec<&str> = parts.iter().map(|s| s.as_str()).collect();
    match derive_token(&identity, &parts_ref) {
        Some(token) => cstring_or_null(token),
        None => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn PortalRootHostJSON(c_relay_url: *const c_char) -> *mut c_char {
    let url = match to_rust_string(c_relay_url) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    match portal_root_host(&url) {
        Some(host) => cstring_or_null(host),
        None => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn LeaseHostnameJSON(c_name: *const c_char, c_root_host: *const c_char) -> *mut c_char {
    let name = match to_rust_string(c_name) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    let root = match to_rust_string(c_root_host) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    match lease_hostname(&name, &root) {
        Some(h) => cstring_or_null(h),
        None => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn NormalizeDNSLabelJSON(c_label: *const c_char) -> *mut c_char {
    let label = match to_rust_string(c_label) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    match normalize_dns_label(&label) {
        Some(out) => cstring_or_null(out),
        None => ptr::null_mut(),
    }
}

// ---------- StreamLease helpers ----------

#[derive(Serialize)]
struct StreamLeaseECHOut {
    #[serde(rename = "route_hostname")]
    route_hostname: String,
    #[serde(rename = "hostname_hash")]
    hostname_hash: String,
}

#[derive(Serialize)]
struct StreamLeaseExtrasOut {
    #[serde(rename = "public_hostname")]
    public_hostname: String,
    #[serde(rename = "route_hostname")]
    route_hostname: String,
    #[serde(rename = "hostname_hash")]
    hostname_hash: String,
}

#[no_mangle]
pub extern "C" fn StreamLeaseECHJSON(c_identity_json: *const c_char, c_public_hostname: *const c_char, c_root_host: *const c_char) -> *mut c_char {
    let identity: Identity = match to_rust_string(c_identity_json) {
        Some(s) => match serde_json::from_str(&s) {
            Ok(i) => i,
            Err(_) => return ptr::null_mut(),
        },
        None => return ptr::null_mut(),
    };
    let public_hostname = match to_rust_string(c_public_hostname) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    let root_host = match to_rust_string(c_root_host) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };

    let route_token = match derive_token(&identity, &["ech-route", &public_hostname, &root_host]) {
        Some(t) => t,
        None => return ptr::null_mut(),
    };
    let mut hasher = Sha256::new();
    hasher.update(route_token.as_bytes());
    let route_sum = hasher.finalize();
    let route_label = format!("ech-{}", base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &route_sum[..20]));
    let route_hostname = match lease_hostname(&route_label, &root_host) {
        Some(h) => h,
        None => return ptr::null_mut(),
    };

    let out = StreamLeaseECHOut {
        route_hostname,
        hostname_hash: hostname_hash(&public_hostname),
    };
    json_or_null(&out)
}

#[no_mangle]
pub extern "C" fn StreamLeaseExtrasJSON(c_identity_json: *const c_char, c_relay_url: *const c_char) -> *mut c_char {
    let identity: Identity = match to_rust_string(c_identity_json) {
        Some(s) => match serde_json::from_str(&s) {
            Ok(i) => i,
            Err(_) => return ptr::null_mut(),
        },
        None => return ptr::null_mut(),
    };
    let relay_url = match to_rust_string(c_relay_url) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    let root_host = match portal_root_host(&relay_url) {
        Some(h) => h,
        None => return ptr::null_mut(),
    };
    let public_hostname = match lease_hostname(&identity.name, &root_host) {
        Some(h) => h,
        None => return ptr::null_mut(),
    };

    let route_token = match derive_token(&identity, &["ech-route", &public_hostname, &root_host]) {
        Some(t) => t,
        None => return ptr::null_mut(),
    };
    let mut hasher = Sha256::new();
    hasher.update(route_token.as_bytes());
    let route_sum = hasher.finalize();
    let route_label = format!("ech-{}", base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &route_sum[..20]));
    let route_hostname = match lease_hostname(&route_label, &root_host) {
        Some(h) => h,
        None => return ptr::null_mut(),
    };
    let hostname_hash_val = hostname_hash(&public_hostname);

    let out = StreamLeaseExtrasOut {
        public_hostname,
        route_hostname,
        hostname_hash: hostname_hash_val,
    };
    json_or_null(&out)
}
