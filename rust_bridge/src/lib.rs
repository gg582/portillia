use std::ffi::{CStr, CString};
use std::str::FromStr;
use libc::{c_char, c_int, c_longlong};
use serde::Serialize;
use siwe::Message;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

fn to_rust_str(c_str: *const c_char) -> Option<&'static str> {
    if c_str.is_null() {
        return None;
    }
    unsafe {
        let bytes = CStr::from_ptr(c_str).to_bytes();
        std::str::from_utf8(bytes).ok()
    }
}

#[no_mangle]
pub extern "C" fn VerifySIWESignature(c_message: *const c_char, c_signature: *const c_char, c_expected_address: *const c_char) -> c_int {
    let msg_str = match to_rust_str(c_message) {
        Some(s) => s,
        None => return 0,
    };
    let sig_str = match to_rust_str(c_signature) {
        Some(s) => s,
        None => return 0,
    };
    let expected_addr = match to_rust_str(c_expected_address) {
        Some(s) => s,
        None => return 0,
    };

    let message = match Message::from_str(msg_str) {
        Ok(m) => m,
        Err(_) => return 0,
    };

    // Address check
    let hex_addr = format!("0x{}", hex::encode(message.address));
    if !hex_addr.eq_ignore_ascii_case(expected_addr) {
        return 0;
    }

    // Decode signature
    let sig_clean = if sig_str.starts_with("0x") || sig_str.starts_with("0X") {
        &sig_str[2..]
    } else {
        sig_str
    };
    let sig_bytes = match hex::decode(sig_clean) {
        Ok(b) => b,
        Err(_) => return 0,
    };

    if sig_bytes.len() != 65 {
        return 0;
    }
    let mut sig_arr = [0u8; 65];
    sig_arr.copy_from_slice(&sig_bytes);
    
    match message.verify_eip191(&sig_arr) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

#[no_mangle]
pub extern "C" fn VerifySIWEMessageJSON(
    c_message: *const c_char,
    c_signature: *const c_char,
    c_domain: *const c_char,
    c_nonce: *const c_char,
    c_now_unix: c_longlong,
) -> *mut c_char {
    let msg_str = match to_rust_str(c_message) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let sig_str = match to_rust_str(c_signature) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let domain_str = match to_rust_str(c_domain) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let nonce_str = match to_rust_str(c_nonce) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };

    let message = match Message::from_str(msg_str) {
        Ok(m) => m,
        Err(_) => return std::ptr::null_mut(),
    };

    if message.domain.as_str() != domain_str {
        return std::ptr::null_mut();
    }
    if message.nonce.as_str() != nonce_str {
        return std::ptr::null_mut();
    }

    let sig_clean = if sig_str.starts_with("0x") || sig_str.starts_with("0X") {
        &sig_str[2..]
    } else {
        sig_str
    };
    let sig_bytes = match hex::decode(sig_clean) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    if sig_bytes.len() != 65 {
        return std::ptr::null_mut();
    }
    let mut sig_arr = [0u8; 65];
    sig_arr.copy_from_slice(&sig_bytes);

    if message.verify_eip191(&sig_arr).is_err() {
        return std::ptr::null_mut();
    }

    let now = match OffsetDateTime::from_unix_timestamp(c_now_unix as i64) {
        Ok(t) => t,
        Err(_) => return std::ptr::null_mut(),
    };
    if let Some(exp) = message.expiration_time {
        if now > *exp.as_ref() {
            return std::ptr::null_mut();
        }
    }
    if let Some(nbf) = message.not_before {
        if now < *nbf.as_ref() {
            return std::ptr::null_mut();
        }
    }

    #[derive(Serialize)]
    struct Out {
        address: String,
    }
    let out = Out {
        address: format!("0x{}", hex::encode(message.address)),
    };

    let out_json = match serde_json::to_string(&out) {
        Ok(j) => j,
        Err(_) => return std::ptr::null_mut(),
    };

    CString::new(out_json).map(|c| c.into_raw()).unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn CreateSIWEMessage(
    c_domain: *const c_char,
    c_address: *const c_char,
    c_uri: *const c_char,
    c_nonce: *const c_char,
    c_statement: *const c_char,
    c_request_id: *const c_char,
    c_issued_at: *const c_char,
    c_expiration_time: *const c_char,
    c_chain_id: c_int,
) -> *mut c_char {
    let domain = to_rust_str(c_domain).unwrap_or("").to_string();
    let address_str = to_rust_str(c_address).unwrap_or("");
    let uri = to_rust_str(c_uri).unwrap_or("").to_string();
    let nonce = to_rust_str(c_nonce).unwrap_or("").to_string();
    let statement = to_rust_str(c_statement).map(|s| s.to_string());
    let request_id = to_rust_str(c_request_id).map(|s| s.to_string());
    
    let clean_addr = if address_str.starts_with("0x") || address_str.starts_with("0X") {
        &address_str[2..]
    } else {
        address_str
    };
    let addr_bytes = match hex::decode(clean_addr) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    if addr_bytes.len() != 20 {
        return std::ptr::null_mut();
    }
    let mut addr_arr = [0u8; 20];
    addr_arr.copy_from_slice(&addr_bytes);

    let issued_at = to_rust_str(c_issued_at)
        .and_then(|s| OffsetDateTime::parse(s, &Rfc3339).ok())
        .map(|t| t.into());
    let expiration_time = to_rust_str(c_expiration_time)
        .and_then(|s| OffsetDateTime::parse(s, &Rfc3339).ok())
        .map(|t| t.into());

    let message = Message {
        domain: domain.parse().unwrap(),
        address: addr_arr,
        statement,
        uri: uri.parse().unwrap(),
        version: siwe::Version::V1,
        chain_id: c_chain_id as u64,
        nonce,
        issued_at: issued_at.unwrap_or_else(|| OffsetDateTime::now_utc().into()),
        expiration_time,
        not_before: None,
        request_id,
        resources: vec![],
    };

    CString::new(message.to_string()).map(|c| c.into_raw()).unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn FreeRustString(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}
