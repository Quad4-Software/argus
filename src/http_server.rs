//! Minimal HTTP/1.1 server for the daemon control plane + webhook receiver.
//! std::net only; one thread per connection, bounded body size.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Read one request; returns None on malformed input.
fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 8192];
    // read headers
    let mut header_end = None;
    while header_end.is_none() && buf.len() < 1 << 20 {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        header_end = find_subslice(&buf, b"\r\n\r\n");
    }
    let he = header_end?;
    let head = String::from_utf8_lossy(&buf[..he]).to_string();
    let mut lines = head.split("\r\n");
    let mut parts = lines.next()?.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let mut headers = Vec::new();
    let mut clen = 0usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let v = v.trim();
            if k.eq_ignore_ascii_case("content-length") {
                clen = v.parse().unwrap_or(0).min(8 << 20);
            }
            headers.push((k.trim().to_string(), v.to_string()));
        }
    }
    let mut body = buf[he + 4..].to_vec();
    while body.len() < clen {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(clen);
    Some(Request {
        method,
        path,
        headers,
        body,
    })
}

fn find_subslice(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

pub fn respond(stream: &mut TcpStream, status: u16, body: &str, content_type: &str) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let out = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-length: {}\r\ncontent-type: {content_type}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(out.as_bytes());
}

/// Serve requests on `listener`, calling `handler` per connection.
pub fn serve(
    listener: TcpListener,
    handler: impl Fn(Request) -> (u16, String) + Send + Sync + 'static,
) {
    let handler = std::sync::Arc::new(handler);
    for stream in listener.incoming() {
        let Ok(mut s) = stream else { continue };
        let h = handler.clone();
        std::thread::spawn(move || {
            if let Some(req) = read_request(&mut s) {
                let (code, body) = h(req);
                respond(&mut s, code, &body, "application/json");
            }
        });
    }
}
