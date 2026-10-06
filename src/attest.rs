// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Offline verification of sigstore bundles (cosign attest/sign),
//! npm publish attestations, and legacy .sig/.cert pairs.
//!
//! Verified end to end without shelling out to cosign:
//!   - DSSE envelope signature under the embedded Fulcio leaf cert
//!   - leaf -> intermediate -> embedded Fulcio root chain
//!   - Rekor signed-entry-timestamp and Merkle inclusion proof
//!   - checkpoint signature under the Rekor transparency log key
//!   - artifact digest match against the attestation subject

use base64::Engine;
use sha2::{Digest, Sha256, Sha512};
use std::path::Path;
use x509_parser::prelude::FromDer;

const FULCIO_ROOT_V1: &str = include_str!("../trust/fulcio_v1.crt.pem");
const FULCIO_ROOT_LEGACY: &str = include_str!("../trust/fulcio.crt.pem");
const FULCIO_INTERMEDIATE_V1: &str = include_str!("../trust/fulcio_intermediate_v1.crt.pem");
const REKOR_PUB: &str = include_str!("../trust/rekor.pub");

fn b64d(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .ok()
}

fn hex_encode(b: impl AsRef<[u8]>) -> String {
    b.as_ref().iter().map(|x| format!("{x:02x}")).collect()
}

/// What a verification run concluded.
#[derive(Debug, Default)]
pub struct AttestReport {
    /// dsse | message-signature | sig+cert | none
    pub kind: String,
    /// The payload/bundle signature verified under the signing cert.
    pub signature_ok: bool,
    /// Signing cert chains to an embedded Fulcio root.
    pub chain_ok: bool,
    /// Rekor tlog entry verified (SET + merkle + checkpoint).
    pub tlog_ok: Option<bool>,
    /// Subject Alternative Names on the signing cert (identity URIs).
    pub identities: Vec<String>,
    /// Signer OIDC issuer (github/gitlab token issuer).
    pub issuer: Option<String>,
    /// Build workflow / repo ref from cert extensions when present.
    pub source_repo: Option<String>,
    /// Artifact digest matches the attested subject (None = not checked).
    pub artifact_match: Option<bool>,
    /// Decoded in-toto statement for display.
    pub statement: Option<serde_json::Value>,
    /// Non-fatal notes and hard failures.
    pub errors: Vec<String>,
}

impl AttestReport {
    pub fn verdict(&self) -> &'static str {
        if !self.signature_ok {
            "FAIL"
        } else if self.tlog_ok == Some(true) {
            "VERIFIED" // signature + transparency log, chain adds identity
        } else if self.signature_ok && self.chain_ok {
            "PARTIAL (signature+chain ok, tlog unverified or absent)"
        } else {
            "UNVERIFIED"
        }
    }
}

struct ParsedCert {
    sans: Vec<String>,
    issuer_ext: Option<String>,
    source_repo: Option<String>,
    spki: Vec<u8>,
    /// The subject key's own algorithm (what signs payloads)
    key_alg: KeyAlg,
    /// (tbs_der, signature, curve) - signature alg oid resolved
    sig_alg: SigAlg,
    tbs: Vec<u8>,
    signature: Vec<u8>,
    self_signed: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum KeyAlg {
    Ec,
    Rsa,
    Other,
}

#[derive(Clone, Copy, PartialEq)]
enum SigAlg {
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    RsaSha256,
    RsaSha384,
    RsaSha512,
    Other,
}

fn sig_alg(oid: &x509_parser::asn1_rs::Oid) -> SigAlg {
    // 1.2.840.10045.4.3.2 ecdsa-sha256, .3.3 sha384, 1.2.840.113549.1.1.11 rsa-sha256
    let s = oid.to_string();
    match s.as_str() {
        "1.2.840.10045.4.3.2" => SigAlg::EcdsaP256Sha256,
        "1.2.840.10045.4.3.3" => SigAlg::EcdsaP384Sha384,
        "1.2.840.113549.1.1.11" => SigAlg::RsaSha256,
        "1.2.840.113549.1.1.12" => SigAlg::RsaSha384,
        "1.2.840.113549.1.1.13" => SigAlg::RsaSha512,
        _ => SigAlg::Other,
    }
}

fn key_alg(c: &x509_parser::certificate::X509Certificate) -> KeyAlg {
    match c
        .tbs_certificate
        .subject_pki
        .algorithm
        .algorithm
        .to_string()
        .as_str()
    {
        "1.2.840.113549.1.1.1" => KeyAlg::Rsa,
        "1.2.840.10045.2.1" => KeyAlg::Ec,
        _ => KeyAlg::Other,
    }
}

fn parse_cert(der: &[u8]) -> Result<ParsedCert, String> {
    let (_, c) =
        x509_parser::prelude::X509Certificate::from_der(der).map_err(|e| format!("x509: {e}"))?;
    let mut sans = Vec::new();
    let mut issuer_ext = None;
    let mut source_repo = None;
    for ext in c.extensions() {
        let oid = ext.oid.to_string();
        if oid == "2.5.29.17"
            && let Ok((_, san)) =
                x509_parser::extensions::SubjectAlternativeName::from_der(ext.value)
        {
            for gn in &san.general_names {
                if let x509_parser::extensions::GeneralName::URI(uri) = gn {
                    sans.push(uri.to_string());
                } else if let x509_parser::extensions::GeneralName::RFC822Name(m) = gn {
                    sans.push(format!("mailto:{m}"));
                }
            }
        }
        // sigstore extension space 1.3.6.1.4.1.57264.1.x
        let ext_str = |v: &[u8]| {
            String::from_utf8_lossy(v)
                .trim_matches(|c: char| c == '"' || c.is_control())
                .to_string()
        };
        match oid.as_str() {
            "1.3.6.1.4.1.57264.1.1" => issuer_ext = Some(ext_str(ext.value)),
            "1.3.6.1.4.1.57264.1.3" | "1.3.6.1.4.1.57264.1.12" => {
                source_repo = Some(ext_str(ext.value))
            }
            _ => {}
        }
    }
    let spki = c
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .to_vec();
    Ok(ParsedCert {
        sans,
        issuer_ext,
        source_repo,
        spki,
        key_alg: key_alg(&c),
        sig_alg: sig_alg(&c.signature_algorithm.algorithm),
        tbs: c.tbs_certificate.as_ref().to_vec(),
        signature: c.signature_value.data.to_vec(),
        self_signed: c.issuer() == c.subject(),
    })
}

fn rsa_verify(alg: SigAlg, spki_der: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, String> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pkcs8::DecodePublicKey;
    use rsa::{pkcs1v15, signature::Verifier};
    // spki_sec1 here is the BITSTRING payload = DER RSAPublicKey {n,e};
    // fall back to a full SPKI blob for publicKey-hint bundles
    let pk = rsa::RsaPublicKey::from_pkcs1_der(spki_der)
        .or_else(|_| rsa::RsaPublicKey::from_public_key_der(spki_der))
        .map_err(|e| format!("rsa key: {e}"))?;
    let s = rsa::pkcs1v15::Signature::try_from(sig).map_err(|e| format!("rsa sig: {e}"))?;
    macro_rules! v {
        ($d:ty) => {
            pkcs1v15::VerifyingKey::<$d>::new(pk.clone())
                .verify(msg, &s)
                .is_ok()
        };
    }
    Ok(match alg {
        SigAlg::RsaSha256 => v!(rsa::sha2::Sha256),
        SigAlg::RsaSha384 => v!(rsa::sha2::Sha384),
        SigAlg::RsaSha512 => v!(rsa::sha2::Sha512),
        _ => return Ok(false),
    })
}

fn verify_ecdsa(alg: SigAlg, spki_sec1: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, String> {
    match alg {
        SigAlg::EcdsaP256Sha256 => {
            use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            let vk =
                VerifyingKey::from_sec1_bytes(spki_sec1).map_err(|e| format!("p256 key: {e}"))?;
            let s = Signature::from_der(sig).map_err(|e| format!("sig der: {e}"))?;
            Ok(vk.verify(msg, &s).is_ok())
        }
        SigAlg::EcdsaP384Sha384 => {
            use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            let vk =
                VerifyingKey::from_sec1_bytes(spki_sec1).map_err(|e| format!("p384 key: {e}"))?;
            let s = Signature::from_der(sig).map_err(|e| format!("sig der: {e}"))?;
            Ok(vk.verify(msg, &s).is_ok())
        }
        a @ (SigAlg::RsaSha256 | SigAlg::RsaSha384 | SigAlg::RsaSha512) => {
            rsa_verify(a, spki_sec1, msg, sig)
        }
        SigAlg::Other => Ok(false),
    }
}

/// Verify `child` was signed by `issuer`'s SPKI.
fn cert_signed_by(child: &ParsedCert, issuer_spki: &[u8]) -> bool {
    verify_ecdsa(child.sig_alg, issuer_spki, &child.tbs, &child.signature).unwrap_or(false)
}

/// Payload signatures verify under the signer's KEY, whose curve is what
/// matters - a cert's own signatureAlgorithm belongs to its issuer.
/// Detect the curve from the SEC1 point length (65=P-256, 97=P-384).
fn verify_by_spki(
    spki_sec1: &[u8],
    key_alg: KeyAlg,
    msg: &[u8],
    sig: &[u8],
) -> Result<bool, String> {
    match key_alg {
        KeyAlg::Rsa => {
            // try the sha256/384/512 variants - the digest used at sign
            // time is not carried on the key
            for a in [SigAlg::RsaSha256, SigAlg::RsaSha384, SigAlg::RsaSha512] {
                if rsa_verify(a, spki_sec1, msg, sig)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        KeyAlg::Other => {
            // probe by shape: EC points start 0x04, RSA keys are DER seqs
            if spki_sec1.first() == Some(&0x04) {
                match spki_sec1.len() {
                    97 => verify_ecdsa(SigAlg::EcdsaP384Sha384, spki_sec1, msg, sig),
                    _ => verify_ecdsa(SigAlg::EcdsaP256Sha256, spki_sec1, msg, sig),
                }
            } else if rsa_verify(SigAlg::RsaSha256, spki_sec1, msg, sig).unwrap_or(false) {
                Ok(true)
            } else {
                Ok(false)
            }
        }
        KeyAlg::Ec => match spki_sec1.len() {
            97 => verify_ecdsa(SigAlg::EcdsaP384Sha384, spki_sec1, msg, sig),
            _ => verify_ecdsa(SigAlg::EcdsaP256Sha256, spki_sec1, msg, sig),
        },
    }
}

/// SEC1 public key point out of an SPKI DER blob (last N bytes of the
/// bitstring - x509-parser hands us the contents already; the outer DER
/// ends with the point for the ec keys we see).
fn spki_point(spki: &[u8]) -> &[u8] {
    // uncompressed point: 0x04 || X || Y
    match spki.len() {
        65 | 97 => spki,
        _ => {
            // SPKI DER: the point sits at the end for secp keys
            for len in [97usize, 65] {
                if spki.len() >= len && spki[spki.len() - len] == 0x04 {
                    return &spki[spki.len() - len..];
                }
            }
            spki
        }
    }
}

fn pem_blocks(pem: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut cur: Option<String> = None;
    for l in pem.lines() {
        if l.contains("BEGIN CERTIFICATE") {
            cur = Some(String::new());
        } else if l.contains("END CERTIFICATE") {
            if let Some(b) = cur.take()
                && let Ok(d) = base64::engine::general_purpose::STANDARD.decode(b)
            {
                out.push(d);
            }
        } else if let Some(b) = cur.as_mut() {
            b.push_str(l.trim());
        }
    }
    out
}

fn trusted_roots() -> Vec<Vec<u8>> {
    let mut r = pem_blocks(FULCIO_ROOT_V1);
    r.extend(pem_blocks(FULCIO_ROOT_LEGACY));
    r
}

fn chain_to_root(leaf: &ParsedCert, bundle_chain: &[Vec<u8>]) -> bool {
    // candidates: bundle intermediates + embedded intermediate + roots
    let mut pool: Vec<ParsedCert> = bundle_chain
        .iter()
        .filter_map(|d| parse_cert(d).ok())
        .collect();
    for pem in [FULCIO_INTERMEDIATE_V1] {
        for d in pem_blocks(pem) {
            if let Ok(c) = parse_cert(&d) {
                pool.push(c);
            }
        }
    }
    let roots: Vec<ParsedCert> = trusted_roots()
        .iter()
        .filter_map(|d| parse_cert(d).ok())
        .collect();
    let mut cur = leaf;
    for _ in 0..6 {
        for root in &roots {
            if cur.self_signed && cert_signed_by(cur, &root.spki) || cert_signed_by(cur, &root.spki)
            {
                return true;
            }
        }
        let next = pool.iter().find(|c| cert_signed_by(cur, &c.spki));
        match next {
            Some(n) => cur = n,
            None => return false,
        }
    }
    false
}

/// DSSE PAE: DSSEv1 <len(type)> <type> <len(body)> <body>
fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"DSSEv1 ");
    v.extend_from_slice(payload_type.len().to_string().as_bytes());
    v.push(b' ');
    v.extend_from_slice(payload_type.as_bytes());
    v.push(b' ');
    v.extend_from_slice(payload.len().to_string().as_bytes());
    v.push(b' ');
    v.extend_from_slice(payload);
    v
}

/// RFC6962 compact inclusion proof: rekor emits only the siblings that
/// exist, so at each level a clear index bit means "right sibling" only
/// when that subtree is within treeSize. Right-edge leaves carry far
/// fewer siblings than the tree depth.
fn merkle_root(body: &[u8], index: u64, tree_size: u64, siblings: &[Vec<u8>]) -> Vec<u8> {
    let mut h = Sha256::digest([b"\x00".as_slice(), body].concat()).to_vec();
    let mut it = siblings.iter();
    let mut j = 0u64;
    while (1u64 << j) < tree_size {
        if (index >> j) & 1 == 1 {
            let Some(s) = it.next() else { break };
            h = Sha256::digest([b"\x01".as_slice(), s, &h].concat()).to_vec();
        } else {
            let base = (index >> j) << j;
            let mid = base + (1 << j);
            if mid + (1 << j) <= tree_size {
                let Some(s) = it.next() else { break };
                h = Sha256::digest([b"\x01".as_slice(), &h, s].concat()).to_vec();
            }
        }
        j += 1;
    }
    h
}

fn pubkey_der(pem: &str) -> Option<Vec<u8>> {
    let b: String = pem
        .lines()
        .filter(|l| !l.contains("PUBLIC KEY") && !l.trim().is_empty())
        .collect();
    b64d(&b)
}

fn rekor_pubkey() -> Option<(p256::ecdsa::VerifyingKey, Vec<u8>)> {
    use p256::ecdsa::VerifyingKey;
    let der = pubkey_der(REKOR_PUB)?;
    // SPKI DER: last 65 bytes are the uncompressed secp256r1 point
    let pt = &der[der.len() - 65..];
    Some((VerifyingKey::from_sec1_bytes(pt).ok()?, der))
}

/// Load a PEM public key for a private rekor instance (--rekor-pub).
/// Supports secp256r1 secp384r1 and RSA keys.
pub fn load_log_key(pem: &str) -> Result<LogKey, String> {
    let der = pubkey_der(pem).ok_or("rekor-pub: no PEM public key")?;
    let kind = {
        let pt = spki_point(&der);
        if pt.len() == 97 {
            LogKeyKind::P384(pt.to_vec())
        } else if pt.len() == 65 && pt[0] == 4 {
            LogKeyKind::P256(pt.to_vec())
        } else {
            LogKeyKind::Rsa(der.clone())
        }
    };
    Ok(LogKey {
        spki_der: der,
        kind,
    })
}

pub enum LogKeyKind {
    P256(Vec<u8>),
    P384(Vec<u8>),
    Rsa(Vec<u8>),
}

/// A transparency-log verification key plus its expected keyId
/// (sha256 of the SPKI DER - that is what bundle logIds carry).
pub struct LogKey {
    pub spki_der: Vec<u8>,
    kind: LogKeyKind,
}

impl LogKey {
    fn key_id(&self) -> Vec<u8> {
        Sha256::digest(&self.spki_der).to_vec()
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        use p256::ecdsa::{Signature as S256, signature::Verifier as V256};
        use p384::ecdsa::{Signature as S384, signature::Verifier as V384};
        match &self.kind {
            LogKeyKind::P256(pt) => p256::ecdsa::VerifyingKey::from_sec1_bytes(pt)
                .ok()
                .zip(S256::from_der(sig).ok())
                .map(|(k, s)| V256::verify(&k, msg, &s).is_ok())
                .unwrap_or(false),
            LogKeyKind::P384(pt) => p384::ecdsa::VerifyingKey::from_sec1_bytes(pt)
                .ok()
                .zip(S384::from_der(sig).ok())
                .map(|(k, s)| V384::verify(&k, msg, &s).is_ok())
                .unwrap_or(false),
            LogKeyKind::Rsa(der) => [SigAlg::RsaSha256, SigAlg::RsaSha384, SigAlg::RsaSha512]
                .iter()
                .any(|a| rsa_verify(*a, der, msg, sig).unwrap_or(false)),
        }
    }
}

/// The embedded production rekor.sigstore.dev key.
fn production_log_key() -> Option<LogKey> {
    let (_, der) = rekor_pubkey()?;
    let kind = LogKeyKind::P256(spki_point(&der).to_vec());
    Some(LogKey {
        spki_der: der,
        kind,
    })
}

/// Checkpoint note signature: last line `--- rekor.sigstore.dev <sig>`
/// over the preceding text. Rekor signs the note body including the
/// trailing newline before the signature block.
fn verify_checkpoint(envelope: &str, key: &LogKey) -> Result<bool, String> {
    // signed-note format: body lines, a blank separator, then
    // "--- name <b64 of keyid4 || sig>". The signature covers the body
    // text ending in a single newline; the first 4 bytes of the decoded
    // signature block are a key-id hint, not key material.
    let i = envelope
        .find("\n\n\u{2014} ")
        .ok_or("checkpoint has no signature block")?;
    let mut body = envelope[..i].to_string();
    body.push('\n');
    // skip the 2-byte newline pair + 3-byte em dash + space
    let sig_b64 = envelope[i + 5..].split_whitespace().last().unwrap_or("");
    let raw = b64d(sig_b64).ok_or("checkpoint sig b64")?;
    let sig = raw.get(4..).ok_or("checkpoint sig too short")?;
    Ok(key.verify(body.as_bytes(), sig))
}

fn verify_tlog(entries: &[serde_json::Value], log_key: &LogKey, rep: &mut AttestReport) {
    let want_id = log_key.key_id();
    let mut any_ok = false;
    for e in entries {
        let entry_id = e["logId"]["keyId"].as_str().and_then(b64d);
        if entry_id.as_ref() != Some(&want_id) {
            rep.errors.push(
                "tlog entry signed by an unknown rekor instance (keyId mismatch);                  pass --rekor-pub for private logs"
                    .into(),
            );
            continue;
        }
        let body_b64 = e["canonicalizedBody"].as_str().unwrap_or("");
        let body = b64d(body_b64);
        let set = e["inclusionPromise"]["signedEntryTimestamp"]
            .as_str()
            .and_then(b64d);
        let proof = &e["inclusionProof"];
        let log_id_hex = e["logId"]["keyId"]
            .as_str()
            .and_then(b64d)
            .map(hex_encode)
            .unwrap_or_default();
        let itime = e["integratedTime"]
            .as_str()
            .and_then(|s| s.parse::<i64>().ok())
            .or_else(|| e["integratedTime"].as_i64())
            .unwrap_or(0);
        if let (Some(body), Some(set)) = (body.as_ref(), set.as_ref()) {
            // SET covers the RFC8785-canonical RekorPayload - ints, not
            // the string forms the bundle uses
            let payload = format!(
                "{{\"body\":\"{}\",\"integratedTime\":{},\"logID\":\"{}\",\"logIndex\":{}}}",
                body_b64,
                itime,
                log_id_hex,
                e["logIndex"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .or_else(|| e["logIndex"].as_u64())
                    .unwrap_or(0)
            );
            let set_ok = log_key.verify(payload.as_bytes(), set);
            if set_ok {
                let idx = proof["logIndex"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .or_else(|| proof["logIndex"].as_u64())
                    .unwrap_or(0);
                let tsize = proof["treeSize"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .or_else(|| proof["treeSize"].as_u64())
                    .unwrap_or(0);
                let sibs: Vec<Vec<u8>> = proof["hashes"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|h| h.as_str().and_then(b64d)).collect())
                    .unwrap_or_default();
                let root_enc = proof["rootHash"].as_str().unwrap_or("");
                let computed = merkle_root(body, idx, tsize, &sibs);
                let want = b64d(root_enc).or_else(|| hex_decode(root_enc));
                let merkle_ok = want.map(|w| w == computed).unwrap_or(false);
                let cp_ok = proof["checkpoint"]["envelope"]
                    .as_str()
                    .and_then(|env| verify_checkpoint(env, log_key).ok())
                    .unwrap_or(false);
                if merkle_ok && cp_ok {
                    any_ok = true;
                } else {
                    rep.errors.push(format!(
                        "tlog detail: SET ok, merkle={merkle_ok} checkpoint={cp_ok}"
                    ));
                }
            } else {
                rep.errors.push("SET signature invalid".into());
            }
        }
    }
    rep.tlog_ok = Some(any_ok);
    if !any_ok {
        rep.errors
            .push("rekor inclusion proof could not be verified".into());
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or(0))
            .collect(),
    )
}

fn leaf_and_chain(vm: &serde_json::Value) -> (Option<Vec<u8>>, Vec<Vec<u8>>) {
    let leaf = vm["certificate"]["rawBytes"].as_str().and_then(b64d);
    let chain: Vec<Vec<u8>> = vm["x509CertificateChain"]["certificates"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|c| c["rawBytes"].as_str().and_then(b64d))
                .collect()
        })
        .unwrap_or_default();
    (leaf.or_else(|| chain.first().cloned()), chain)
}

/// Verify a sigstore bundle JSON (new bundle format).
pub fn verify_bundle(bytes: &[u8], artifact: Option<&Path>) -> AttestReport {
    verify_bundle_key(bytes, artifact, None)
}

/// `log_key` overrides the rekor verification key for private instances.
pub fn verify_bundle_key(
    bytes: &[u8],
    artifact: Option<&Path>,
    log_key: Option<&LogKey>,
) -> AttestReport {
    let mut rep = AttestReport::default();
    let v: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(e) => {
            rep.errors.push(format!("bundle json: {e}"));
            rep.kind = "none".into();
            return rep;
        }
    };
    let vm = &v["verificationMaterial"];
    let (leaf_der, chain) = leaf_and_chain(vm);
    // publicKey bundles (npm publish attestations) carry no cert - the
    // signer's PEM key lives inside the rekor canonicalizedBody
    let pk_hint: Option<Vec<u8>> = if leaf_der.is_none() {
        vm["tlogEntries"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|e| e["canonicalizedBody"].as_str())
            .and_then(b64d)
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| {
                v["spec"]["content"]["envelope"]["signatures"]
                    .as_array()
                    .and_then(|a| a.first())
                    .and_then(|s| s["publicKey"].as_str().map(|x| x.to_string()))
            })
            .and_then(|pemb64| b64d(&pemb64))
    } else {
        None
    };
    // spki for payload verification: cert leaf, or the publicKey from tlog
    let (leaf_spki, leaf_key_alg, leaf_cert) = match (leaf_der.as_ref(), pk_hint.as_ref()) {
        (Some(d), _) => {
            let c = match parse_cert(d) {
                Ok(c) => c,
                Err(e) => {
                    rep.errors.push(e);
                    rep.kind = "none".into();
                    return rep;
                }
            };
            (c.spki.clone(), c.key_alg, Some(c))
        }
        (None, Some(pem)) => {
            // PEM public key: decode the base64 body, take the SEC1 point
            let body: String = String::from_utf8_lossy(pem)
                .lines()
                .filter(|l| !l.contains("PUBLIC KEY") && !l.trim().is_empty())
                .collect();
            let der = b64d(&body).unwrap_or_default();
            (spki_point(&der).to_vec(), KeyAlg::Other, None)
        }
        _ => {
            rep.errors
                .push("no signing certificate or public key in bundle".into());
            rep.kind = "none".into();
            return rep;
        }
    };
    if let Some(leaf) = &leaf_cert {
        rep.identities = leaf.sans.clone();
        rep.issuer = leaf.issuer_ext.clone();
        rep.source_repo = leaf.source_repo.clone();
    }
    rep.chain_ok = match &leaf_cert {
        Some(leaf) => {
            let chain_ders: Vec<Vec<u8>> = chain.iter().skip(1).cloned().collect();
            let ok = chain_to_root(leaf, &chain_ders);
            if !ok {
                rep.errors
                    .push("cert chain does not reach a Fulcio root".into());
            }
            ok
        }
        None => false, // registry-key attestations have no fulcio chain
    };

    // payload signature
    if let Some(env) = v.get("dsseEnvelope") {
        rep.kind = "dsse".into();
        let payload = env["payload"].as_str().and_then(b64d).unwrap_or_default();
        let ptype = env["payloadType"].as_str().unwrap_or("");
        let sig_b = env["signatures"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|s| s["sig"].as_str())
            .and_then(b64d)
            .unwrap_or_default();
        let msg = pae(ptype, &payload);
        rep.signature_ok =
            verify_by_spki(&leaf_spki, leaf_key_alg, &msg, &sig_b).unwrap_or_else(|e| {
                rep.errors.push(e);
                false
            });
        if !rep.signature_ok {
            rep.errors.push("dsse signature invalid".into());
        }
        rep.statement = serde_json::from_slice(&payload).ok();
        // artifact digest match: sha256 or sha512 subject digest
        if let Some(p) = artifact
            && let Some(st) = &rep.statement
            && let Ok(b) = std::fs::read(p)
        {
            let dg256 = hex_encode(Sha256::digest(&b));
            let dg512 = hex_encode(Sha512::digest(&b));
            let subs = st["subject"].as_array().cloned().unwrap_or_default();
            rep.artifact_match = Some(
                !subs.is_empty()
                    && subs.iter().any(|s| {
                        s["digest"]["sha256"].as_str() == Some(dg256.as_str())
                            || s["digest"]["sha512"].as_str() == Some(dg512.as_str())
                    }),
            );
        }
    } else if v.get("messageSignature").is_some() {
        rep.kind = "message-signature".into();
        let sig_b = v["messageSignature"]["signature"]
            .as_str()
            .and_then(b64d)
            .unwrap_or_default();
        let digest = v["messageSignature"]["messageDigest"]["digest"]
            .as_str()
            .and_then(b64d)
            .unwrap_or_default();
        let mut candidates: Vec<Vec<u8>> = Vec::new();
        if let Some(p) = artifact
            && let Ok(b) = std::fs::read(p)
        {
            let dg = Sha256::digest(&b);
            rep.artifact_match = Some(hex_encode(&dg) == hex_encode(&digest) || digest.is_empty());
            candidates.push(b); // cosign signs raw blob
            candidates.push(hex_encode(&dg).into_bytes()); // or hex digest
        }
        if !digest.is_empty() {
            candidates.push(digest.clone());
            candidates.push(hex_encode(&digest).into_bytes());
        }
        rep.signature_ok = candidates
            .iter()
            .any(|m| verify_by_spki(&leaf_spki, leaf_key_alg, m, &sig_b).unwrap_or(false));
        if !rep.signature_ok {
            rep.errors
                .push("message signature could not be verified against known candidates".into());
        }
    } else {
        rep.kind = "none".into();
        rep.errors
            .push("bundle has no dsseEnvelope or messageSignature".into());
    }

    // tlog entries
    if let Some(t) = vm["tlogEntries"].as_array()
        && !t.is_empty()
    {
        let owned;
        let key = match log_key {
            Some(k) => k,
            None => {
                owned = production_log_key();
                match owned.as_ref() {
                    Some(k) => k,
                    None => {
                        rep.errors.push("rekor pubkey unavailable".into());
                        return rep;
                    }
                }
            }
        };
        verify_tlog(t, key, &mut rep);
    }
    rep
}

/// Legacy cosign pair: verify `sig` over the artifact digest under `cert`.
pub fn verify_sig_cert(sig_bytes: &[u8], cert_der: &[u8], artifact: &[u8]) -> AttestReport {
    let mut rep = AttestReport {
        kind: "sig+cert".into(),
        ..Default::default()
    };
    let leaf = match parse_cert(cert_der) {
        Ok(c) => c,
        Err(e) => {
            rep.errors.push(e);
            return rep;
        }
    };
    rep.identities = leaf.sans.clone();
    rep.issuer = leaf.issuer_ext.clone();
    rep.source_repo = leaf.source_repo.clone();
    rep.chain_ok = chain_to_root(&leaf, &[]);
    let dg = Sha256::digest(artifact);
    let candidates = [artifact.to_vec(), hex_encode(&dg).into_bytes(), dg.to_vec()];
    rep.signature_ok = candidates
        .iter()
        .any(|m| verify_by_spki(&leaf.spki, leaf.key_alg, m, sig_bytes).unwrap_or(false));
    if !rep.signature_ok {
        rep.errors
            .push("signature invalid under cert over artifact candidates".into());
    }
    rep
}

/// npm publish attestations for a package: fetch then verify each bundle.
pub fn verify_npm(http: &crate::http::HttpClient, pkg: &str) -> Result<Vec<AttestReport>, String> {
    let url = format!("https://registry.npmjs.org/-/npm/v1/attestations/{pkg}");
    let v = http
        .get_json(&url)
        .map_err(|e| format!("npm attestations {pkg}: {e}"))?;
    let bundles = v["attestations"].as_array().cloned().unwrap_or_default();
    if bundles.is_empty() {
        return Err(format!("no attestations published for {pkg}"));
    }
    let mut out = Vec::new();
    for a in bundles {
        let bytes = serde_json::to_vec(&a["bundle"]).map_err(|e| e.to_string())?;
        let mut rep = verify_bundle(&bytes, None);
        rep.statement
            .get_or_insert(serde_json::json!({}))
            .as_object_mut()
            .map(|o| o.insert("_predicateType".into(), a["predicateType"].clone()));
        out.push(rep);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_provenance_bundle_verifies_offline() {
        let b = std::fs::read("tests/fixtures/attest-bundle.json").unwrap();
        let rep = verify_bundle(&b, None);
        assert!(rep.signature_ok, "sig failed: {:?}", rep.errors);
        assert!(rep.chain_ok, "chain failed: {:?}", rep.errors);
        assert_eq!(rep.tlog_ok, Some(true), "tlog failed: {:?}", rep.errors);
        assert_eq!(rep.verdict(), "VERIFIED");
        assert!(
            rep.identities
                .iter()
                .any(|i| i.contains("release-integration.yml"))
        );
        assert_eq!(
            rep.issuer.as_deref(),
            Some("https://token.actions.githubusercontent.com")
        );
    }

    #[test]
    fn artifact_digest_matches_attested_subject() {
        let b = std::fs::read("tests/fixtures/attest-bundle.json").unwrap();
        let rep = verify_bundle(&b, Some(Path::new("tests/fixtures/attest-artifact.tgz")));
        assert_eq!(rep.artifact_match, Some(true));
    }

    #[test]
    fn rsa_signed_bundle_verifies() {
        // self-signed RSA cert: chain must fail (not a Fulcio root) but
        // the RSA payload signature itself must verify
        let b = std::fs::read("tests/fixtures/attest-rsa-bundle.json").unwrap();
        let rep = verify_bundle(&b, None);
        assert!(rep.signature_ok, "rsa sig failed: {:?}", rep.errors);
        assert!(!rep.chain_ok);
        assert_eq!(rep.verdict(), "UNVERIFIED");
    }

    #[test]
    fn unknown_tlog_instance_fails_closed() {
        let b = std::fs::read("tests/fixtures/attest-bundle.json").unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        // rekey the logId so the embedded rekor key no longer matches
        v["verificationMaterial"]["tlogEntries"][0]["logId"]["keyId"] =
            serde_json::json!("dW5rbm93bi1rZXktaWQtMzJieXRlc3dlc3Rlcg==");
        let rep = verify_bundle(&serde_json::to_vec(&v).unwrap(), None);
        assert!(
            rep.errors
                .iter()
                .any(|e| e.contains("unknown rekor instance"))
        );
        // signature+chain still verify; only the tlog is unverifiable
        assert!(rep.verdict().starts_with("PARTIAL"));
    }

    #[test]
    fn tampered_payload_fails() {
        let b = std::fs::read("tests/fixtures/attest-tampered.json").unwrap();
        let rep = verify_bundle(&b, None);
        assert!(!rep.signature_ok);
        assert_eq!(rep.verdict(), "FAIL");
    }
}
