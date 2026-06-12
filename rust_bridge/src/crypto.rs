use std::ffi::{c_char, c_int, c_longlong, CStr, CString};
use std::ptr;
use serde::{Deserialize, Serialize};
use base64::{engine::general_purpose::STANDARD as BASE64_STD, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL, Engine};
use sha2::{Sha256, Digest as Sha2Digest};
use sha3::{Keccak256, Digest as Sha3Digest};
use secp256k1::{Message, PublicKey, SecretKey, Secp256k1};

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

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    hex::decode(s).ok()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

fn pubkey_to_address(pubkey_uncompressed: &[u8]) -> Option<String> {
    if pubkey_uncompressed.len() != 65 || pubkey_uncompressed[0] != 0x04 {
        return None;
    }
    let hash = keccak256(&pubkey_uncompressed[1..]);
    let addr_lower: String = hash[12..32].iter().map(|b| format!("{:02x}", b)).collect();
    let checksum_hash = keccak256(addr_lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in addr_lower.chars().enumerate() {
        if c.is_ascii_digit() {
            out.push(c);
        } else {
            let nibble = checksum_hash[i / 2];
            let n = if i % 2 == 0 { nibble >> 4 } else { nibble & 0x0f };
            if n > 7 {
                out.push(c.to_ascii_uppercase());
            } else {
                out.push(c);
            }
        }
    }
    Some(out)
}

fn parse_secret_key(priv_hex: &str) -> Option<SecretKey> {
    let bytes = hex_decode(priv_hex)?;
    if bytes.len() != 32 { return None; }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    SecretKey::from_slice(&arr).ok()
}

fn derive_address_from_private_key(priv_hex: &str) -> Option<String> {
    let sk = parse_secret_key(priv_hex)?;
    let secp = Secp256k1::new();
    let pk = PublicKey::from_secret_key(&secp, &sk);
    let uncompressed = pk.serialize_uncompressed();
    pubkey_to_address(&uncompressed)
}

fn sign_sha256_compact_b64(message: &[u8], priv_hex: &str) -> Option<String> {
    let sk = parse_secret_key(priv_hex)?;
    let hash = sha256(message);
    let msg = Message::from_digest(hash);
    let secp = Secp256k1::new();
    let sig = secp.sign_ecdsa_recoverable(&msg, &sk);
    let (recid, compact64) = sig.serialize_compact();
    let mut compact65 = [0u8; 65];
    // Ethereum-style recovery id: 27 + recid + 4 = 31 + recid
    compact65[0] = 31 + recid.to_i32() as u8;
    compact65[1..].copy_from_slice(&compact64);
    Some(BASE64_STD.encode(&compact65))
}

fn decode_compact_sig(sig_b64: &str) -> Option<Vec<u8>> {
    let s = sig_b64.trim();
    // Try URL-safe no-padding first (JWT), then standard base64.
    BASE64_URL.decode(s).ok().or_else(|| BASE64_STD.decode(s).ok())
}

fn recover_pubkey_from_compact_b64(message: &[u8], sig_b64: &str) -> Option<PublicKey> {
    let sig_bytes = decode_compact_sig(sig_b64)?;
    if sig_bytes.len() != 65 { return None; }
    let first = sig_bytes[0];
    let recid = if first >= 31 { first - 31 } else { first };
    if recid > 3 { return None; }
    let hash = sha256(message);
    let msg = Message::from_digest(hash);
    let secp = Secp256k1::new();
    let recid = secp256k1::ecdsa::RecoveryId::from_i32(recid as i32).ok()?;
    let sig = secp256k1::ecdsa::RecoverableSignature::from_compact(&sig_bytes[1..], recid).ok()?;
    secp.recover_ecdsa(&msg, &sig).ok()
}

fn recover_address_from_compact_b64(message: &[u8], sig_b64: &str) -> Option<String> {
    let pk = recover_pubkey_from_compact_b64(message, sig_b64)?;
    pubkey_to_address(&pk.serialize_uncompressed())
}

fn verify_compact_b64(message: &[u8], sig_b64: &str, expected_address: &str) -> bool {
    match recover_address_from_compact_b64(message, sig_b64) {
        Some(addr) => addr.eq_ignore_ascii_case(expected_address),
        None => false,
    }
}

fn verify_compact_b64_with_pubkey(message: &[u8], sig_b64: &str, expected_pubkey_hex: &str) -> bool {
    let pk = match recover_pubkey_from_compact_b64(message, sig_b64) {
        Some(pk) => pk,
        None => return false,
    };
    let expected = match hex_decode(expected_pubkey_hex) {
        Some(b) => b,
        None => return false,
    };
    let expected_pk = match PublicKey::from_slice(&expected) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    pk == expected_pk
}

// ---------- Descriptor ----------

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RelayDescriptor {
    #[serde(default)]
    address: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    sequence: u64,
    #[serde(default)]
    version_val: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issued_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    #[serde(default, rename = "issued_at_unix_nano")]
    issued_at_unix_nano: i64,
    #[serde(default, rename = "expires_at_unix_nano")]
    expires_at_unix_nano: i64,
    #[serde(default, rename = "api_https_addr")]
    api_https_addr: String,
    #[serde(default, rename = "wireguard_public_key")]
    wireguard_public_key: String,
    #[serde(default, rename = "wireguard_port")]
    wireguard_port: i32,
    #[serde(default, rename = "overlay_ipv4")]
    overlay_ipv4: String,
    #[serde(default, rename = "overlay_cidrs")]
    overlay_cidrs: Vec<String>,
    #[serde(default)]
    supports_overlay: bool,
    #[serde(default, rename = "supports_overlay_peer")]
    supports_overlay_peer: bool,
    #[serde(default)]
    supports_udp: bool,
    #[serde(default)]
    supports_tcp: bool,
    #[serde(default)]
    active_connections: i64,
    #[serde(default, rename = "tcp_bps")]
    tcp_bps: f64,
    #[serde(default)]
    load: f64,
    #[serde(default, rename = "load_score")]
    load_score: f64,
    #[serde(default, rename = "last_updated")]
    last_updated: i64,
    #[serde(default)]
    signature: String,
}

fn fmt_bool(b: bool) -> &'static str { if b { "true" } else { "false" } }

fn build_canonical_descriptor_json_long(d: &RelayDescriptor) -> String {
    // Matches src/portal/discovery/discovery.c build_canonical_descriptor_json
    let mut out = String::new();
    out.push_str("{\"address\":\""); out.push_str(&d.address);
    out.push_str("\",\"version\":\""); out.push_str(&d.version);
    out.push_str("\",\"sequence\":"); out.push_str(&d.sequence.to_string());
    out.push_str(",\"version_val\":"); out.push_str(&d.version_val.to_string());
    out.push_str(",\"issued_at_unix_nano\":"); out.push_str(&d.issued_at_unix_nano.to_string());
    out.push_str(",\"expires_at_unix_nano\":"); out.push_str(&d.expires_at_unix_nano.to_string());
    out.push_str(",\"api_https_addr\":\""); out.push_str(&d.api_https_addr);
    out.push_str("\",\"wireguard_public_key\":\""); out.push_str(&d.wireguard_public_key);
    out.push_str("\",\"wireguard_port\":"); out.push_str(&d.wireguard_port.to_string());
    out.push_str(",\"overlay_ipv4\":\""); out.push_str(&d.overlay_ipv4);
    out.push_str("\",\"overlay_cidrs\":[");
    for (i, c) in d.overlay_cidrs.iter().enumerate() {
        if i > 0 { out.push(','); }
        out.push('"'); out.push_str(c); out.push('"');
    }
    out.push_str("],\"supports_overlay\":"); out.push_str(fmt_bool(d.supports_overlay));
    out.push_str(",\"supports_overlay_peer\":"); out.push_str(fmt_bool(d.supports_overlay_peer));
    out.push_str(",\"supports_udp\":"); out.push_str(fmt_bool(d.supports_udp));
    out.push_str(",\"supports_tcp\":"); out.push_str(fmt_bool(d.supports_tcp));
    out.push_str(",\"active_connections\":"); out.push_str(&d.active_connections.to_string());
    out.push_str(",\"tcp_bps\":"); out.push_str(&format!("{:.17}", d.tcp_bps));
    out.push_str(",\"load\":"); out.push_str(&format!("{:.17}", d.load));
    out.push_str(",\"load_score\":"); out.push_str(&format!("{:.17}", d.load_score));
    out.push_str(",\"last_updated\":"); out.push_str(&d.last_updated.to_string());
    out.push('}');
    out
}

fn build_canonical_descriptor_json_short(d: &RelayDescriptor) -> String {
    // Matches src/discovery/relay_set.c build_canonical_descriptor_json
    let mut out = String::new();
    out.push_str("{\"address\":\""); out.push_str(&d.address);
    out.push_str("\",\"version\":\""); out.push_str(&d.version);
    out.push_str("\",\"issued_at_unix_nano\":"); out.push_str(&d.issued_at_unix_nano.to_string());
    out.push_str(",\"expires_at_unix_nano\":"); out.push_str(&d.expires_at_unix_nano.to_string());
    out.push_str(",\"api_https_addr\":\""); out.push_str(&d.api_https_addr);
    out.push_str("\",\"wireguard_public_key\":\""); out.push_str(&d.wireguard_public_key);
    out.push_str("\",\"wireguard_port\":"); out.push_str(&d.wireguard_port.to_string());
    out.push_str(",\"supports_overlay\":"); out.push_str(fmt_bool(d.supports_overlay));
    out.push_str(",\"supports_udp\":"); out.push_str(fmt_bool(d.supports_udp));
    out.push_str(",\"supports_tcp\":"); out.push_str(fmt_bool(d.supports_tcp));
    out.push_str(",\"active_connections\":"); out.push_str(&d.active_connections.to_string());
    out.push_str(",\"tcp_bps\":"); out.push_str(&format!("{:.17}", d.tcp_bps));
    out.push('}');
    out
}

fn descriptor_from_input_json(json: &str) -> Option<RelayDescriptor> {
    let mut d: RelayDescriptor = serde_json::from_str(json).ok()?;
    // Convert RFC3339 issued_at/expires_at to unix nano if present and numeric fields are zero.
    if d.issued_at_unix_nano == 0 {
        if let Some(ref s) = d.issued_at {
            if let Ok(t) = s.parse::<i64>() {
                d.issued_at_unix_nano = t * 1_000_000_000;
            }
        }
    }
    if d.expires_at_unix_nano == 0 {
        if let Some(ref s) = d.expires_at {
            if let Ok(t) = s.parse::<i64>() {
                d.expires_at_unix_nano = t * 1_000_000_000;
            }
        }
    }
    Some(d)
}

#[no_mangle]
pub extern "C" fn SignDescriptorJSON(c_desc_json: *const c_char, c_private_key_hex: *const c_char) -> *mut c_char {
    let json = match to_rust_string(c_desc_json) { Some(s) => s, None => return ptr::null_mut() };
    let priv_hex = match to_rust_string(c_private_key_hex) { Some(s) => s, None => return ptr::null_mut() };
    let mut desc = match descriptor_from_input_json(&json) { Some(d) => d, None => return ptr::null_mut() };
    let canonical = build_canonical_descriptor_json_long(&desc);
    let sig = match sign_sha256_compact_b64(canonical.as_bytes(), &priv_hex) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    desc.signature = sig;
    json_or_null(&desc)
}

#[no_mangle]
pub extern "C" fn VerifyDescriptorJSON(c_desc_json: *const c_char) -> *mut c_char {
    let json = match to_rust_string(c_desc_json) { Some(s) => s, None => return ptr::null_mut() };
    let desc = match descriptor_from_input_json(&json) { Some(d) => d, None => return ptr::null_mut() };
    if desc.signature.is_empty() || desc.address.is_empty() { return ptr::null_mut(); }
    let canonical_long = build_canonical_descriptor_json_long(&desc);
    if verify_compact_b64(canonical_long.as_bytes(), &desc.signature, &desc.address) {
        return json_or_null(&desc);
    }
    let canonical_short = build_canonical_descriptor_json_short(&desc);
    if verify_compact_b64(canonical_short.as_bytes(), &desc.signature, &desc.address) {
        return json_or_null(&desc);
    }
    ptr::null_mut()
}

// ---------- Hop Route ----------

#[derive(Debug, Clone, Deserialize, Serialize)]
struct HopRoute {
    #[serde(default, rename = "owner_public_key")]
    owner_public_key: String,
    #[serde(default, rename = "relay_url")]
    relay_url: String,
    #[serde(default, rename = "public_hostname")]
    public_hostname: String,
    #[serde(default, rename = "route_hostname")]
    route_hostname: String,
    #[serde(default, rename = "hostname_hash")]
    hostname_hash: String,
    #[serde(default, rename = "ech_config_list")]
    ech_config_list: String,
    #[serde(default, rename = "match_token")]
    match_token: String,
    #[serde(default, rename = "forward_token")]
    forward_token: String,
    #[serde(default, rename = "forward_relay")]
    forward_relay: serde_json::Value,
    #[serde(default, rename = "first_seen_at_unix_nano")]
    first_seen_at_unix_nano: i64,
    #[serde(default, rename = "expires_at_unix_nano")]
    expires_at_unix_nano: i64,
    #[serde(default)]
    purpose: String,
    #[serde(default)]
    method: String,
    #[serde(default)]
    signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Identity {
    #[serde(default)]
    name: String,
    #[serde(default)]
    address: String,
    #[serde(default, rename = "private_key")]
    private_key: String,
    #[serde(default, rename = "public_key")]
    public_key: String,
}

fn build_hop_route_canonical(route: &HopRoute, method: &str) -> String {
    let method_upper = method.to_ascii_uppercase();
    let mut out = String::new();
    out.push_str("{\"purpose\":\"portal hop route v1\",\"method\":\"");
    out.push_str(&method_upper);
    out.push_str("\",\"owner_public_key\":\""); out.push_str(&route.owner_public_key);
    out.push_str("\",\"relay_url\":\""); out.push_str(&route.relay_url);
    out.push_str("\",\"public_hostname\":\""); out.push_str(&route.public_hostname);
    out.push_str("\",\"route_hostname\":\""); out.push_str(&route.route_hostname);
    out.push_str("\",\"hostname_hash\":\""); out.push_str(&route.hostname_hash);
    out.push_str("\",\"ech_config_list\":\""); out.push_str(&route.ech_config_list);
    out.push_str("\",\"match_token\":\""); out.push_str(&route.match_token);
    out.push_str("\",\"forward_relay\":"); out.push_str(&route.forward_relay.to_string());
    out.push_str(",\"forward_token\":\""); out.push_str(&route.forward_token);
    out.push_str("\",\"first_seen_at_unix_nano\":"); out.push_str(&route.first_seen_at_unix_nano.to_string());
    out.push_str(",\"expires_at_unix_nano\":"); out.push_str(&route.expires_at_unix_nano.to_string());
    out.push('}');
    out
}

#[no_mangle]
pub extern "C" fn SignHopRouteJSON(c_route_json: *const c_char, c_method: *const c_char, c_identity_json: *const c_char, c_expires_at_unix: c_longlong) -> *mut c_char {
    let json = match to_rust_string(c_route_json) { Some(s) => s, None => return ptr::null_mut() };
    let method = match to_rust_string(c_method) { Some(s) => s, None => return ptr::null_mut() };
    let identity_json = match to_rust_string(c_identity_json) { Some(s) => s, None => return ptr::null_mut() };
    let identity: Identity = match serde_json::from_str(&identity_json) { Ok(i) => i, Err(_) => return ptr::null_mut() };
    let mut route: HopRoute = match serde_json::from_str(&json) { Ok(r) => r, Err(_) => return ptr::null_mut() };
    route.expires_at_unix_nano = c_expires_at_unix * 1_000_000_000;
    let priv_key = if identity.private_key.is_empty() { identity.public_key } else { identity.private_key };
    let canonical = build_hop_route_canonical(&route, &method);
    let sig = match sign_sha256_compact_b64(canonical.as_bytes(), &priv_key) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    route.signature = sig;
    json_or_null(&route)
}

#[no_mangle]
pub extern "C" fn VerifyHopRouteJSON(c_route_json: *const c_char, c_method: *const c_char) -> *mut c_char {
    let json = match to_rust_string(c_route_json) { Some(s) => s, None => return ptr::null_mut() };
    let method = match to_rust_string(c_method) { Some(s) => s, None => return ptr::null_mut() };
    let route: HopRoute = match serde_json::from_str(&json) { Ok(r) => r, Err(_) => return ptr::null_mut() };
    if route.signature.is_empty() || route.owner_public_key.is_empty() { return ptr::null_mut(); }
    let canonical = build_hop_route_canonical(&route, &method);
    if verify_compact_b64(canonical.as_bytes(), &route.signature, &route.owner_public_key) {
        json_or_null(&route)
    } else {
        ptr::null_mut()
    }
}

// ---------- Lease Token (ES256K JWT) ----------

#[derive(Debug, Clone, Deserialize, Serialize)]
struct LeaseClaims {
    #[serde(default)]
    sub: String,
    #[serde(default, rename = "identity_name")]
    identity_name: String,
    #[serde(default, rename = "identity_address")]
    identity_address: String,
    #[serde(default)]
    iss: String,
    #[serde(default)]
    aud: String,
    #[serde(default)]
    kid: String,
    #[serde(default)]
    iat: i64,
    #[serde(default)]
    exp: i64,
}

fn b64url_json<T: Serialize>(v: &T) -> Option<String> {
    serde_json::to_vec(v).ok().map(|b| BASE64_URL.encode(&b))
}

fn sign_es256k_jwt(header_b64: &str, payload_b64: &str, priv_hex: &str) -> Option<String> {
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let sig_b64 = sign_sha256_compact_b64(signing_input.as_bytes(), priv_hex)?;
    // Re-encode signature bytes with base64url (compact sig is base64 std, decode then re-encode).
    let sig_bytes = BASE64_STD.decode(&sig_b64).ok()?;
    Some(BASE64_URL.encode(&sig_bytes))
}

#[no_mangle]
pub extern "C" fn IssueLeaseTokenJSON(c_private_key_hex: *const c_char, c_key_id: *const c_char, c_issuer: *const c_char, c_identity_json: *const c_char, c_ttl_seconds: c_int) -> *mut c_char {
    let priv_hex = match to_rust_string(c_private_key_hex) { Some(s) => s, None => return ptr::null_mut() };
    let key_id = match to_rust_string(c_key_id) { Some(s) => s, None => return ptr::null_mut() };
    let issuer = match to_rust_string(c_issuer) { Some(s) => s, None => return ptr::null_mut() };
    let identity_json = match to_rust_string(c_identity_json) { Some(s) => s, None => return ptr::null_mut() };
    let identity: Identity = match serde_json::from_str(&identity_json) { Ok(i) => i, Err(_) => return ptr::null_mut() };

    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let exp = now + c_ttl_seconds as i64;
    let claims = LeaseClaims {
        sub: identity.address.clone(),
        identity_name: identity.name.clone(),
        identity_address: identity.address.clone(),
        iss: issuer.clone(),
        aud: issuer.clone(),
        kid: key_id.clone(),
        iat: now,
        exp,
    };

    let header = serde_json::json!({"alg":"ES256K","typ":"JWT"});
    let header_b64 = match b64url_json(&header) { Some(s) => s, None => return ptr::null_mut() };
    let payload_b64 = match b64url_json(&claims) { Some(s) => s, None => return ptr::null_mut() };
    let sig_b64 = match sign_es256k_jwt(&header_b64, &payload_b64, &priv_hex) { Some(s) => s, None => return ptr::null_mut() };
    let token = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

    #[derive(Serialize)]
    struct Out {
        token: String,
        claims: LeaseClaims,
    }
    json_or_null(&Out { token, claims })
}

#[no_mangle]
pub extern "C" fn VerifyLeaseTokenJSON(c_token: *const c_char, c_public_key_hex: *const c_char, c_issuer: *const c_char, c_now_unix: c_longlong) -> *mut c_char {
    let token = match to_rust_string(c_token) { Some(s) => s, None => return ptr::null_mut() };
    let pub_hex = match to_rust_string(c_public_key_hex) { Some(s) => s, None => return ptr::null_mut() };
    let issuer = match to_rust_string(c_issuer) { Some(s) => s, None => return ptr::null_mut() };

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 { return ptr::null_mut(); }
    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let sig_b64 = parts[2];

    // Verify signature over header.payload
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    if !verify_compact_b64_with_pubkey(signing_input.as_bytes(), sig_b64, &pub_hex) {
        return ptr::null_mut();
    }

    let payload_json = match BASE64_URL.decode(payload_b64.trim_end_matches('=')) {
        Ok(v) => match String::from_utf8(v) { Ok(s) => s, Err(_) => return ptr::null_mut() },
        Err(_) => return ptr::null_mut(),
    };
    let claims: LeaseClaims = match serde_json::from_str(&payload_json) { Ok(c) => c, Err(_) => return ptr::null_mut() };

    if !claims.iss.eq_ignore_ascii_case(&issuer) { return ptr::null_mut(); }
    if !claims.aud.eq_ignore_ascii_case(&issuer) { return ptr::null_mut(); }
    if c_now_unix > claims.exp { return ptr::null_mut(); }

    json_or_null(&claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn c(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    fn free(s: *mut c_char) {
        if !s.is_null() {
            unsafe { let _ = CString::from_raw(s); }
        }
    }

    fn generate_key() -> (String, String) {
        let secp = Secp256k1::new();
        let sk = SecretKey::new(&mut rand::thread_rng());
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let priv_hex = hex::encode(sk.secret_bytes());
        let addr = pubkey_to_address(&pk.serialize_uncompressed()).unwrap();
        (priv_hex, addr)
    }

    #[test]
    fn descriptor_sign_verify_roundtrip() {
        let (priv_hex, addr) = generate_key();
        let desc = format!(
            "{{\"address\":\"{}\",\"version\":\"8\",\"sequence\":1,\"version_val\":8,\"issued_at_unix_nano\":1000000000000000000,\"expires_at_unix_nano\":1000000000000000300,\"api_https_addr\":\"https://localhost\",\"wireguard_public_key\":\"\",\"wireguard_port\":0,\"overlay_ipv4\":\"\",\"overlay_cidrs\":[],\"supports_overlay\":false,\"supports_overlay_peer\":false,\"supports_udp\":false,\"supports_tcp\":true,\"active_connections\":0,\"tcp_bps\":0.0,\"load\":0.0,\"load_score\":0.0,\"last_updated\":0}}",
            addr
        );
        let signed = SignDescriptorJSON(c(&desc).as_ptr(), c(&priv_hex).as_ptr());
        assert!(!signed.is_null());
        let signed_str = unsafe { CStr::from_ptr(signed).to_str().unwrap().to_string() };
        assert!(signed_str.contains("signature\""));
        free(signed);

        // Re-sign so VerifyDescriptorJSON has a signature to check.
        let signed2 = SignDescriptorJSON(c(&desc).as_ptr(), c(&priv_hex).as_ptr());
        let verified = VerifyDescriptorJSON(signed2);
        assert!(!verified.is_null());
        free(verified);
        free(signed2);
    }

    #[test]
    fn lease_token_issue_verify_roundtrip() {
        let (priv_hex, addr) = generate_key();
        let identity = format!("{{\"name\":\"test\",\"address\":\"{}\"}}", addr);
        let token_json = IssueLeaseTokenJSON(c(&priv_hex).as_ptr(), c("kid1").as_ptr(), c("issuer").as_ptr(), c(&identity).as_ptr(), 3600);
        assert!(!token_json.is_null());
        let token_json_str = unsafe { CStr::from_ptr(token_json).to_str().unwrap().to_string() };
        let parsed: serde_json::Value = serde_json::from_str(&token_json_str).unwrap();
        let token = parsed["token"].as_str().unwrap().to_string();
        free(token_json);

        // Derive public key hex for verification.
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&hex::decode(&priv_hex).unwrap()).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let pub_hex = format!("0x{}", hex::encode(pk.serialize_uncompressed()));

        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        let claims = VerifyLeaseTokenJSON(c(&token).as_ptr(), c(&pub_hex).as_ptr(), c("issuer").as_ptr(), now);
        assert!(!claims.is_null());
        free(claims);
    }
}
