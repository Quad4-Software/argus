// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Optional SMTP recipient check.
//! Off unless the caller passes the flag. A catch-all that accepts a
//! random address is not treated as proof the mailbox exists.

use super::{Hit, Status};
use serde_json::json;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn verdict(real: u16, random: u16) -> (Status, &'static str) {
    if real == 530 || random == 530 {
        return (
            Status::Inconclusive,
            "mail server requires TLS before it will accept a recipient",
        );
    }
    let real_ok = (200..300).contains(&real);
    let random_ok = (200..300).contains(&random);
    let real_no = (500..600).contains(&real);
    let random_no = (500..600).contains(&random);
    if real_ok && !random_ok && random_no {
        return (
            Status::Confirmed,
            "server accepted this address and refused a random one",
        );
    }
    if real_ok && random_ok {
        return (
            Status::Inconclusive,
            "server accepted a random address too, so it looks like a catch-all",
        );
    }
    if real_no && random_no {
        return (Status::Absent, "server refused this address");
    }
    (
        Status::Inconclusive,
        "server reply did not confirm or refuse the address",
    )
}

pub fn skipped() -> Hit {
    Hit::new(
        "smtp",
        Status::Inconclusive,
        "SMTP was not queried. Pass --smtp to ask the mail server",
        None,
    )
}

pub fn probe(host: &str, email: &str) -> Hit {
    if email
        .chars()
        .any(|c| c == '\r' || c == '\n' || c == '<' || c == '>' || c == ' ')
    {
        return Hit::new(
            "smtp",
            Status::Error,
            "address is not safe to send to SMTP",
            None,
        );
    }
    let Some(domain) = email.split('@').nth(1).filter(|d| !d.is_empty()) else {
        return Hit::new("smtp", Status::Error, "address has no domain", None);
    };
    let local = email.split('@').next().unwrap_or("");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut random_local = format!("argus-{stamp:x}");
    if random_local.eq_ignore_ascii_case(local) {
        random_local.push('x');
    }
    let random = format!("{random_local}@{domain}");
    match ask(host, email, &random) {
        Ok((real, fake, banner)) => {
            let (status, summary) = verdict(real, fake);
            Hit::new(
                "smtp",
                status,
                summary,
                Some(json!({
                    "host": host,
                    "real": real,
                    "random": fake,
                    "banner": banner,
                })),
            )
        }
        Err(e) => Hit::new("smtp", Status::Error, e, Some(json!({"host": host}))),
    }
}

fn ask(host: &str, real: &str, random: &str) -> Result<(u16, u16, String), String> {
    let addr = (host, 25u16)
        .to_socket_addrs()
        .map_err(|e| format!("smtp resolve: {e}"))?
        .next()
        .ok_or_else(|| format!("no address for {host}"))?;
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|e| format!("smtp connect: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("smtp timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("smtp timeout: {e}"))?;
    let mut reader = BufReader::new(stream);
    let (code, banner) = read_reply(&mut reader)?;
    if code >= 400 {
        return Err(format!("smtp banner {code}"));
    }
    let (code, _) = cmd(&mut reader, "EHLO argus.invalid")?;
    if !(200..400).contains(&code) {
        return Err(format!("smtp EHLO {code}"));
    }
    let (code, _) = cmd(&mut reader, "MAIL FROM:<>")?;
    if !(200..400).contains(&code) {
        let _ = cmd(&mut reader, "QUIT");
        return Err(format!("smtp MAIL FROM {code}"));
    }
    let (real_code, _) = cmd(&mut reader, &format!("RCPT TO:<{real}>"))?;
    let (random_code, _) = cmd(&mut reader, &format!("RCPT TO:<{random}>"))?;
    let _ = cmd(&mut reader, "QUIT");
    Ok((real_code, random_code, banner.chars().take(160).collect()))
}

fn cmd(reader: &mut BufReader<TcpStream>, line: &str) -> Result<(u16, String), String> {
    let stream = reader.get_mut();
    stream
        .write_all(format!("{line}\r\n").as_bytes())
        .map_err(|e| format!("smtp write: {e}"))?;
    stream.flush().map_err(|e| format!("smtp write: {e}"))?;
    read_reply(reader)
}

fn read_reply(reader: &mut BufReader<TcpStream>) -> Result<(u16, String), String> {
    for _ in 0..20 {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| format!("smtp read: {e}"))?;
        if n == 0 {
            return Err("smtp connection closed".into());
        }
        if line.len() < 4 {
            return Err("short smtp reply".into());
        }
        let code: u16 = line[..3]
            .parse()
            .map_err(|_| "smtp reply had no code".to_string())?;
        if line.as_bytes().get(3) != Some(&b'-') {
            return Ok((code, line.trim().to_string()));
        }
    }
    Err("smtp reply did not finish".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_needs_a_refused_random_recipient() {
        let (status, summary) = verdict(250, 550);
        assert_eq!(status, Status::Confirmed);
        assert!(summary.contains("refused"));
        assert_eq!(verdict(250, 250).0, Status::Inconclusive);
        assert_eq!(verdict(550, 550).0, Status::Absent);
        assert_eq!(verdict(530, 550).0, Status::Inconclusive);
        assert_eq!(verdict(450, 450).0, Status::Inconclusive);
    }
}
