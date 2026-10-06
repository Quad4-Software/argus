// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Detached ed25519 signatures for custom rulesets. A ruleset TOML can
//! carry `<name>.toml.sig` (base64). With `--rules-pubkey <file>` argus
//! refuses to load unsigned or mis-signed custom rules, protecting
//! shared rule channels from silent tampering.

use std::path::Path;

/// Key files are raw 32-byte hex (privkey) / hex(pubkey), one per file.
pub fn keygen(priv_out: &Path, pub_out: &Path) -> Result<String, String> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| e.to_string())?;
    let kp = ed25519_dalek::SigningKey::from_bytes(&seed);
    std::fs::write(priv_out, hex(&kp.to_bytes())).map_err(|e| e.to_string())?;
    std::fs::write(pub_out, hex(&kp.verifying_key().to_bytes())).map_err(|e| e.to_string())?;
    Ok(format!(
        "wrote {} + {}",
        priv_out.display(),
        pub_out.display()
    ))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.len() != 64 {
        return Err("key file must be 64 hex chars (32 bytes)".into());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| "bad hex in key file".to_string())?;
    }
    Ok(out)
}

/// Sign a ruleset file; writes <file>.sig (base64 signature).
pub fn sign(ruleset: &Path, key: &Path) -> Result<String, String> {
    use ed25519_dalek::Signer;
    let hexkey = std::fs::read_to_string(key).map_err(|e| format!("key: {e}"))?;
    let kp = ed25519_dalek::SigningKey::from_bytes(&unhex(&hexkey)?);
    let bytes = std::fs::read(ruleset).map_err(|e| e.to_string())?;
    let sig = kp.sign(&bytes);
    let b64 = b64(&sig.to_bytes());
    let out = ruleset.with_extension("toml.sig");
    std::fs::write(&out, &b64).map_err(|e| e.to_string())?;
    Ok(format!("signed {} -> {}", ruleset.display(), out.display()))
}

/// Verify a ruleset against a public key and its .sig sibling.
pub fn verify(ruleset: &Path, pubkey: &Path) -> Result<(), String> {
    use ed25519_dalek::Verifier;
    let hexkey = std::fs::read_to_string(pubkey).map_err(|e| format!("pubkey: {e}"))?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&unhex(&hexkey)?)
        .map_err(|e| format!("pubkey: {e}"))?;
    let sig_path = ruleset.with_extension("toml.sig");
    let sig_b64 = std::fs::read_to_string(&sig_path)
        .map_err(|_| format!("{}: missing signature {sig_path:?}", ruleset.display()))?;
    let sig_bytes = unb64(sig_b64.trim())?;
    if sig_bytes.len() != 64 {
        return Err(format!("{sig_path:?}: bad signature length"));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&sig_bytes);
    let sig = ed25519_dalek::Signature::from_bytes(&arr);
    let bytes = std::fs::read(ruleset).map_err(|e| e.to_string())?;
    vk.verify(&bytes, &sig)
        .map_err(|_| format!("{}: signature verification failed", ruleset.display()))
}

fn b64(b: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for ch in b.chunks(3) {
        let n = (ch[0] as u32) << 16
            | (ch.get(1).copied().unwrap_or(0) as u32) << 8
            | ch.get(2).copied().unwrap_or(0) as u32;
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        s.push(if ch.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        s.push(if ch.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    s
}

fn unb64(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut nbits = 0;
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err("bad base64".into()),
        };
        buf = (buf << 6) | v as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((buf >> nbits) as u8);
        }
    }
    Ok(out)
}

/// Sign arbitrary bytes; returns the base64 signature.
/// Shared by baseline signing and report attestation.
pub fn sign_bytes(bytes: &[u8], key: &Path) -> Result<String, String> {
    use ed25519_dalek::Signer;
    let hexkey = std::fs::read_to_string(key).map_err(|e| format!("key: {e}"))?;
    let kp = ed25519_dalek::SigningKey::from_bytes(&unhex(&hexkey)?);
    Ok(b64(&kp.sign(bytes).to_bytes()))
}

/// Verify a base64 signature over bytes against a public key file.
pub fn verify_bytes(bytes: &[u8], sig_b64: &str, pubkey: &Path) -> Result<(), String> {
    use ed25519_dalek::Verifier;
    let hexkey = std::fs::read_to_string(pubkey).map_err(|e| format!("pubkey: {e}"))?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&unhex(&hexkey)?)
        .map_err(|e| format!("pubkey: {e}"))?;
    let sig_bytes = unb64(sig_b64.trim())?;
    if sig_bytes.len() != 64 {
        return Err("bad signature length".into());
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&sig_bytes);
    let sig = ed25519_dalek::Signature::from_bytes(&arr);
    vk.verify(bytes, &sig)
        .map_err(|_| "bad signature".to_string())
}
