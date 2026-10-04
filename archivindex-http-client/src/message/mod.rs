//! Parsed views of stored HTTP/1 messages.
//!
//! [`ResponseMetadata`] and [`RequestMetadata`] read the start line and field lines of a stored
//! message and locate its body. They never change the stored bytes.

use std::borrow::Cow;

use crate::parsing::{is_lws, is_token, next_line};

/// Parsed fields and boundaries of a recorded HTTP response message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseMetadata {
    /// Status from the recorded response's first line.
    pub status: u16,
    /// Offset at which the recorded message body begins.
    pub body_offset: usize,
    headers: Fields,
}

impl ResponseMetadata {
    /// Parse a complete HTTP response header section.
    #[must_use]
    pub fn parse(response: &[u8]) -> Option<Self> {
        let head = parse_head(response)?;
        let mut parts = head.start_line.splitn(3, |&byte| byte == b' ');
        let version = parts.next()?;
        let code = parts.next()?;
        if !version.starts_with(b"HTTP/") || code.len() != 3 || !code.iter().all(u8::is_ascii_digit)
        {
            return None;
        }
        let status = code
            .iter()
            .fold(0, |value, &byte| value * 10 + u16::from(byte - b'0'));

        Some(Self {
            status,
            body_offset: head.body_offset,
            headers: head.headers,
        })
    }

    /// Return the first response header value, matched case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        header_value(&self.headers, name)
    }

    /// Return every response header value with this name, in the order received.
    ///
    /// A field may be sent as several lines; a recipient combining them into one value separates
    /// them with a comma (RFC 9110 section 5.3). `Vary` in particular is often split this way.
    pub fn headers<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> {
        header_values(&self.headers, name)
    }

    /// Return the response header value with this name as one combined line.
    ///
    /// See [`combined_field`].
    #[must_use]
    pub fn combined_header(&self, name: &str) -> Option<Cow<'_, str>> {
        combined_field(header_values(&self.headers, name))
    }
}

/// Parsed fields and boundaries of a recorded HTTP request message.
///
/// The response's `Vary` header identifies request fields needed to match a later request against
/// the stored response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestMetadata {
    /// Offset at which the recorded message body begins.
    pub body_offset: usize,
    method: String,
    target: Vec<u8>,
    headers: Fields,
}

impl RequestMetadata {
    /// Parse a complete HTTP request header section.
    ///
    /// The method must be a token and the target must be nonempty. The remaining part of the
    /// request line must begin with `HTTP/`; the version syntax is not fully validated.
    #[must_use]
    pub fn parse(request: &[u8]) -> Option<Self> {
        let head = parse_head(request)?;
        let mut parts = head.start_line.splitn(3, |&byte| byte == b' ');
        let method = parts.next()?;
        let target = parts.next()?;
        let version = parts.next()?;
        if !is_token(method) || target.is_empty() || !version.starts_with(b"HTTP/") {
            return None;
        }

        Some(Self {
            body_offset: head.body_offset,
            // A token is ASCII by definition, so this cannot fail after the check above.
            method: std::str::from_utf8(method).ok()?.to_owned(),
            target: target.to_vec(),
            headers: head.headers,
        })
    }

    /// Return the request method, as it was sent.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Return the request target, as it was sent.
    ///
    /// RFC 9112 confines a request target to ASCII, but a recorded request may carry raw octets
    /// that a client sent unencoded, so this is exposed as bytes rather than as text.
    #[must_use]
    pub fn target(&self) -> &[u8] {
        &self.target
    }

    /// Return the first request header value, matched case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        header_value(&self.headers, name)
    }

    /// Return every request header value with this name, in the order received.
    pub fn headers<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> {
        header_values(&self.headers, name)
    }

    /// Return the request header value with this name as one combined line.
    ///
    /// Matching a request against a `Vary` field compares the selecting fields as combined values
    /// (RFC 9111 section 4.1). See [`combined_field`].
    #[must_use]
    pub fn combined_header(&self, name: &str) -> Option<Cow<'_, str>> {
        combined_field(header_values(&self.headers, name))
    }
}

/// Combine the lines of one field into the value a recipient reads (RFC 9110 section 5.3).
///
/// A single value is borrowed; multiple values are joined with a comma and a space. Use this only
/// for fields that allow comma-separated values, such as `Vary`, and not for fields such as
/// `Set-Cookie`. Returns `None` for no values or invalid UTF-8.
///
/// # Examples
///
/// ```
/// use std::borrow::Cow;
///
/// use archivindex_http_client::message::combined_field;
///
/// let lines = [b"gzip".as_slice(), b"br".as_slice()];
/// assert_eq!(combined_field(lines), Some(Cow::Owned("gzip, br".to_owned())));
/// assert_eq!(combined_field([]), None);
/// ```
pub fn combined_field<'a>(lines: impl IntoIterator<Item = &'a [u8]>) -> Option<Cow<'a, str>> {
    let mut lines = lines.into_iter();
    let first = std::str::from_utf8(lines.next()?).ok()?;
    let Some(second) = lines.next() else {
        return Some(Cow::Borrowed(first));
    };
    let mut combined = first.to_owned();
    for line in std::iter::once(second).chain(lines) {
        combined.push_str(", ");
        combined.push_str(std::str::from_utf8(line).ok()?);
    }

    Some(Cow::Owned(combined))
}

/// The field lines of a message head, in the order received, with their names as sent.
type Fields = Vec<(String, Vec<u8>)>;

/// A parsed header section, less the start line, which each message form reads for itself.
struct Head<'a> {
    start_line: &'a [u8],
    body_offset: usize,
    headers: Fields,
}

/// Split a header section into its start line, its body offset, and its unfolded field lines.
///
/// Accept `CRLF` and bare `LF` line endings. RFC 9112 section 2.2 permits recipients to accept a
/// bare `LF`.
///
/// Returns `None` when the section is unterminated or a field name is not an HTTP token.
fn parse_head(message: &[u8]) -> Option<Head<'_>> {
    let start_line = next_line(message, 0)?;
    let mut offset = start_line.next;
    let mut headers = Fields::new();

    loop {
        let line = next_line(message, offset)?;
        let content = &message[offset..line.end];
        offset = line.next;

        if content.is_empty() {
            return Some(Head {
                start_line: &message[..start_line.end],
                body_offset: offset,
                headers,
            });
        }

        if content.first().copied().is_some_and(is_lws) {
            let (_, value) = headers.last_mut()?;
            value.push(b' ');
            value.extend_from_slice(content.trim_ascii());
            continue;
        }

        let colon = content.iter().position(|&byte| byte == b':')?;
        let name = &content[..colon];
        if !is_token(name) {
            return None;
        }
        let name = std::str::from_utf8(name).ok()?.to_owned();
        headers.push((name, content[colon + 1..].trim_ascii().to_vec()));
    }
}

fn header_values<'h, 'n>(
    headers: &'h [(String, Vec<u8>)],
    name: &'n str,
) -> impl Iterator<Item = &'h [u8]> + use<'h, 'n> {
    headers
        .iter()
        .filter(move |(field, _)| field.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_slice())
}

/// The first value with this name, borrowed from `headers` alone so a caller may pass a temporary.
fn header_value<'h>(headers: &'h [(String, Vec<u8>)], name: &str) -> Option<&'h [u8]> {
    header_values(headers, name).next()
}

#[cfg(test)]
mod tests;
