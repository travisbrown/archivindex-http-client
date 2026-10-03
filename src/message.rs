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
            value.extend_from_slice(trim_ascii(content));
            continue;
        }

        let colon = content.iter().position(|&byte| byte == b':')?;
        let name = &content[..colon];
        if !is_token(name) {
            return None;
        }
        let name = std::str::from_utf8(name).ok()?.to_owned();
        headers.push((name, trim_ascii(&content[colon + 1..]).to_vec()));
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

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &bytes[start..end]
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::{RequestMetadata, ResponseMetadata};

    #[test]
    fn response_metadata_preserves_boundaries_and_header_values() {
        let response = b"HTTP/1.1 206 Partial Content\r\nX-Test: first\r\nx-test: second\r\nX-Binary: \xff\r\n\r\nbody";
        let metadata = ResponseMetadata::parse(response).unwrap();

        assert_eq!(metadata.status, 206);
        assert_eq!(&response[metadata.body_offset..], b"body");
        assert_eq!(metadata.header("X-TEST"), Some(b"first".as_slice()));
        assert_eq!(metadata.header("x-binary"), Some(b"\xff".as_slice()));
    }

    #[test]
    fn response_metadata_unfolds_continuation_lines() {
        let response = b"HTTP/1.0 200 OK\r\nX-Test: one\r\n\ttwo\r\n three\r\n\r\n";
        let metadata = ResponseMetadata::parse(response).unwrap();

        assert_eq!(metadata.header("x-test"), Some(b"one two three".as_slice()));
    }

    /// The head is framed as [`entity_body`](crate::body::entity_body) frames it, bare `LF` included.
    #[test]
    fn response_metadata_reads_lines_ended_with_a_bare_line_feed() {
        let response = b"HTTP/1.1 200 OK\nContent-Type: text/html\r\n\r\nhi";
        let metadata = ResponseMetadata::parse(response).unwrap();

        assert_eq!(metadata.status, 200);
        assert_eq!(
            metadata.header("content-type"),
            Some(b"text/html".as_slice())
        );
        assert_eq!(
            &response[metadata.body_offset..],
            crate::body::entity_body(response).unwrap().as_ref()
        );
    }

    #[test]
    fn response_metadata_rejects_incomplete_or_malformed_messages() {
        assert!(ResponseMetadata::parse(b"HTTP/1.1 200 OK\r\nX: y\r\n").is_none());
        assert!(ResponseMetadata::parse(b"not HTTP\r\n\r\n").is_none());
        assert!(ResponseMetadata::parse(b"HTTP/1.1 20 OK\r\n\r\n").is_none());
    }

    /// Repeated fields are returned in receive order.
    #[test]
    fn repeated_response_headers_are_returned_in_order() {
        let response = b"HTTP/1.1 200 OK\r\nVary: Accept-Encoding\r\nvary: User-Agent\r\n\r\n";
        let metadata = ResponseMetadata::parse(response).unwrap();

        assert_eq!(
            metadata.headers("vary").collect::<Vec<_>>(),
            [b"Accept-Encoding".as_slice(), b"User-Agent".as_slice()]
        );
        assert_eq!(metadata.headers("etag").next(), None);
    }

    #[test]
    fn request_metadata_preserves_boundaries_and_header_values() {
        let request = b"POST /submit?q=1 HTTP/1.1\r\nHost: example.com\r\n\
                        Content-Length: 4\r\nX-Binary: \xff\r\n\r\nbody";
        let metadata = RequestMetadata::parse(request).unwrap();

        assert_eq!(metadata.method(), "POST");
        assert_eq!(metadata.target(), b"/submit?q=1");
        assert_eq!(&request[metadata.body_offset..], b"body");
        assert_eq!(metadata.header("HOST"), Some(b"example.com".as_slice()));
        assert_eq!(metadata.header("x-binary"), Some(b"\xff".as_slice()));
        assert_eq!(metadata.header("accept"), None);
    }

    /// Request metadata exposes every field used to select a representation.
    #[test]
    fn request_metadata_reads_the_fields_that_select_a_representation() {
        let request = b"GET / HTTP/1.1\r\nUser-Agent: MobileBot/1.0\r\n\
                        Accept-Encoding: gzip\r\naccept-encoding: br\r\n\r\n";
        let metadata = RequestMetadata::parse(request).unwrap();

        assert_eq!(
            metadata.header("user-agent"),
            Some(b"MobileBot/1.0".as_slice())
        );
        assert_eq!(
            metadata.headers("Accept-Encoding").collect::<Vec<_>>(),
            [b"gzip".as_slice(), b"br".as_slice()]
        );
    }

    /// The lines of a repeated field combine into the value a `Vary` selection compares.
    #[test]
    fn combined_header_joins_the_lines_of_a_repeated_field() {
        let request = b"GET / HTTP/1.1\r\nAccept-Language: en\r\naccept-language: de\r\n\
                        User-Agent: Bot/1.0\r\nX-Binary: \xff\r\n\r\n";
        let metadata = RequestMetadata::parse(request).unwrap();

        assert_eq!(
            metadata.combined_header("accept-language"),
            Some(Cow::Owned("en, de".to_owned()))
        );
        assert_eq!(
            metadata.combined_header("user-agent"),
            Some(Cow::Borrowed("Bot/1.0"))
        );
        assert_eq!(metadata.combined_header("x-binary"), None);
        assert_eq!(metadata.combined_header("accept"), None);

        let response = b"HTTP/1.1 200 OK\r\nVary: Accept-Encoding\r\n\
                         vary: User-Agent\r\n\r\n";
        let metadata = ResponseMetadata::parse(response).unwrap();

        assert_eq!(
            metadata.combined_header("vary"),
            Some(Cow::Owned("Accept-Encoding, User-Agent".to_owned()))
        );
    }

    #[test]
    fn request_metadata_unfolds_continuation_lines() {
        let request = b"GET / HTTP/1.1\r\nX-Test: one\r\n\ttwo\r\n three\r\n\r\n";
        let metadata = RequestMetadata::parse(request).unwrap();

        assert_eq!(metadata.header("x-test"), Some(b"one two three".as_slice()));
    }

    /// Origin, absolute, authority, and asterisk targets are accepted.
    #[test]
    fn request_metadata_accepts_every_request_target_form() {
        let targets: [&[u8]; 4] = [
            b"/origin",
            b"http://example.com/absolute",
            b"example.com:443",
            b"*",
        ];

        for target in targets {
            let mut request = b"GET ".to_vec();
            request.extend_from_slice(target);
            request.extend_from_slice(b" HTTP/1.1\r\n\r\n");
            let metadata = RequestMetadata::parse(&request).unwrap();

            assert_eq!(metadata.target(), target);
        }
    }

    #[test]
    fn request_metadata_rejects_incomplete_or_malformed_messages() {
        // No terminating blank line.
        assert!(RequestMetadata::parse(b"GET / HTTP/1.1\r\nHost: x\r\n").is_none());
        // A response, which a recorded request must not be.
        assert!(RequestMetadata::parse(b"HTTP/1.1 200 OK\r\n\r\n").is_none());
        // No version.
        assert!(RequestMetadata::parse(b"GET /\r\n\r\n").is_none());
        // A space in the target splits the request line.
        assert!(RequestMetadata::parse(b"GET /a b HTTP/1.1\r\n\r\n").is_none());
        // A method that is not a token.
        assert!(RequestMetadata::parse(b"GE(T / HTTP/1.1\r\n\r\n").is_none());
        assert!(RequestMetadata::parse(b" / HTTP/1.1\r\n\r\n").is_none());
        // A field line without a name.
        assert!(RequestMetadata::parse(b"GET / HTTP/1.1\r\nnocolon\r\n\r\n").is_none());
    }

    /// Invalid field names must not turn malformed heads into reusable HTTP metadata.
    #[test]
    fn metadata_rejects_invalid_field_names() {
        for name in ["", "Bad Name", "ETag ", "Bad\tName", "Bäd", "Bad(Name)"] {
            for start in ["GET / HTTP/1.1", "HTTP/1.1 200 OK"] {
                let message = format!("{start}\r\n{name}: value\r\n\r\n");
                assert!(
                    RequestMetadata::parse(message.as_bytes()).is_none(),
                    "{message:?}"
                );
                assert!(
                    ResponseMetadata::parse(message.as_bytes()).is_none(),
                    "{message:?}"
                );
            }
        }
    }
}
