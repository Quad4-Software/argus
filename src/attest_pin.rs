// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Identity pinning on top of bundle verification. The crypto path
//! stays in attest.rs; this layer checks that a VERIFIED attestation
//! names the repo, signer, or issuer the caller expected - a genuine
//! signature for the wrong thing is a hard failure, not a pass.

use crate::attest::{AttestReport, LogKey, verify_bundle_key};
use std::path::Path;

/// valid-but-wrong attestation cannot satisfy a gate.
#[derive(Debug, Default, Clone)]
pub struct Expect {
    /// Source repo: case-insensitive substring match against the cert's
    /// repo claim, so "org/repo" matches <https://github.com/org/repo>.
    pub repo: Option<String>,
    /// Signer identity (SAN URI): case-insensitive substring match
    /// against any identity on the cert.
    pub identity: Option<String>,
    /// OIDC issuer: exact match only.
    pub issuer: Option<String>,
}

impl Expect {
    pub fn is_empty(&self) -> bool {
        self.repo.is_none() && self.identity.is_none() && self.issuer.is_none()
    }
}

/// Bundle verification with identity pinning on top. The crypto path is
/// identical to verify_bundle_key; expectations are checked afterwards
/// so a signature failure cannot be masked by a pin error.
pub fn verify_bundle_key_expect(
    bytes: &[u8],
    artifact: Option<&Path>,
    log_key: Option<&LogKey>,
    expect: &Expect,
) -> AttestReport {
    let mut rep = verify_bundle_key(bytes, artifact, log_key);
    apply_expectations(&mut rep, expect);
    rep
}

/// Case-insensitive substring match (ASCII-safe via lowercase fold).
fn contains_ci(hay: &str, needle: &str) -> bool {
    hay.to_lowercase().contains(&needle.to_lowercase())
}

fn shown(s: &str) -> &str {
    if s.is_empty() { "<none>" } else { s }
}

/// Check a verified report against expected identity pins. Repo and
/// identity are substring/case-insensitive (users pin "org/repo", the
/// cert carries a full URL); issuer must match exactly because OIDC
/// issuers are canonical URLs where lookalikes matter. A mismatch is a
/// hard failure: the attestation is genuine but for the wrong thing.
pub fn apply_expectations(rep: &mut AttestReport, expect: &Expect) {
    if expect.is_empty() {
        return;
    }
    if let Some(v) = &expect.repo {
        rep.pinned.push(format!("pinned repo: {v}"));
    }
    if let Some(v) = &expect.identity {
        rep.pinned.push(format!("pinned identity: {v}"));
    }
    if let Some(v) = &expect.issuer {
        rep.pinned.push(format!("pinned issuer: {v}"));
    }
    // unauthenticated claims cannot satisfy a pin; the signature
    // failure already fails the verdict on its own
    if !rep.signature_ok {
        return;
    }
    let mut ok = true;
    if let Some(want) = &expect.repo {
        let got = rep.source_repo.clone().unwrap_or_default();
        if !contains_ci(&got, want) {
            ok = false;
            rep.errors.push(format!(
                "identity mismatch: expected repo {want}, attested by {}",
                shown(&got)
            ));
        }
    }
    if let Some(want) = &expect.identity
        && !rep.identities.iter().any(|i| contains_ci(i, want))
    {
        ok = false;
        rep.errors.push(format!(
            "identity mismatch: expected identity {want}, attested by {}",
            shown(&rep.identities.join(", "))
        ));
    }
    if let Some(want) = &expect.issuer {
        let got = rep.issuer.clone().unwrap_or_default();
        if got != *want {
            ok = false;
            rep.errors.push(format!(
                "identity mismatch: expected issuer {want}, attested by {}",
                shown(&got)
            ));
        }
    }
    rep.pins_ok = Some(ok);
}

#[cfg(test)]
mod tests {
    use super::*;

    // the fixture attests https://github.com/npm/node-semver; the short
    // org/repo form must match via suffix/contains
    #[test]
    fn expect_repo_match_stays_verified() {
        let b = std::fs::read("tests/fixtures/attest-bundle.json").unwrap();
        let rep = verify_bundle_key_expect(
            &b,
            None,
            None,
            &Expect {
                repo: Some("npm/node-semver".into()),
                ..Default::default()
            },
        );
        assert_eq!(rep.pins_ok, Some(true), "{:?}", rep.errors);
        assert_eq!(rep.verdict(), "VERIFIED");
        assert!(rep.pinned.iter().any(|p| p.contains("npm/node-semver")));
    }

    #[test]
    fn expect_repo_mismatch_fails() {
        let b = std::fs::read("tests/fixtures/attest-bundle.json").unwrap();
        let rep = verify_bundle_key_expect(
            &b,
            None,
            None,
            &Expect {
                repo: Some("evil/repo".into()),
                ..Default::default()
            },
        );
        assert_eq!(rep.pins_ok, Some(false));
        assert_eq!(rep.verdict(), "FAIL");
        assert!(
            rep.errors
                .iter()
                .any(|e| e.contains("identity mismatch: expected repo"))
        );
    }

    #[test]
    fn expect_issuer_requires_exact_match() {
        let b = std::fs::read("tests/fixtures/attest-bundle.json").unwrap();
        let rep = verify_bundle_key_expect(
            &b,
            None,
            None,
            &Expect {
                issuer: Some("https://token.actions.githubusercontent.com".into()),
                ..Default::default()
            },
        );
        assert_eq!(rep.pins_ok, Some(true), "{:?}", rep.errors);
        let rep = verify_bundle_key_expect(
            &b,
            None,
            None,
            &Expect {
                issuer: Some("https://accounts.google.com".into()),
                ..Default::default()
            },
        );
        assert_eq!(rep.pins_ok, Some(false));
        assert!(
            rep.errors
                .iter()
                .any(|e| e.contains("identity mismatch: expected issuer"))
        );
    }

    #[test]
    fn expect_identity_matches_any_san() {
        let b = std::fs::read("tests/fixtures/attest-bundle.json").unwrap();
        let rep = verify_bundle_key_expect(
            &b,
            None,
            None,
            &Expect {
                identity: Some("release-integration.yml".into()),
                ..Default::default()
            },
        );
        assert_eq!(rep.verdict(), "VERIFIED");
    }
}
