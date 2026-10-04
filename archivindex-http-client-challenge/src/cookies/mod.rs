//! Host-scoped cookies for challenge clearance and caller-supplied values.
//!
//! Cookies are scoped to the exact host. This helper does not implement path, expiry, or `Domain`
//! matching. Cookies marked `Secure`, or supplied for an HTTPS URL, are sent only over HTTPS. It
//! supports supplied and challenge-clearance cookies, not general browser cookie handling.

use std::collections::HashMap;

use http::header::HeaderValue;
use url::Url;

/// Cookies supplied by the caller or issued by a recognized challenge, scoped to an exact host.
#[derive(Debug, Default)]
pub struct CookieJar {
    by_host: HashMap<String, Vec<Cookie>>,
}

/// One `name=value` pair of a `Cookie` field value, and whether it may be sent only over HTTPS.
#[derive(Debug)]
struct Cookie {
    pair: Vec<u8>,
    secure: bool,
}

/// One or more cookie pairs and whether they require HTTPS.
#[derive(Clone, Debug)]
pub struct StoredCookie {
    /// The complete field value, as it is sent.
    pub value: HeaderValue,
    /// Whether the cookie was issued with the `Secure` attribute, or supplied for an HTTPS URL.
    pub secure: bool,
}

impl Cookie {
    /// The name before the `=`, or the whole pair when it has none.
    fn name(&self) -> &[u8] {
        pair_name(&self.pair)
    }
}

/// The `name=value` pairs of a `Cookie` field value, without their surrounding whitespace.
fn pairs(value: &[u8]) -> impl Iterator<Item = &[u8]> {
    value
        .split(|byte| *byte == b';')
        .map(<[u8]>::trim_ascii)
        .filter(|pair| !pair.is_empty())
}

/// The name before the `=` of a `name=value` pair, or the whole pair when it has none.
fn pair_name(pair: &[u8]) -> &[u8] {
    pair.iter()
        .position(|byte| *byte == b'=')
        .map_or(pair, |end| &pair[..end])
}

/// Add a pair to a `Cookie` field value being built, with the separator the grammar uses.
fn extend_pairs(value: &mut Vec<u8>, pair: &[u8]) {
    if !value.is_empty() {
        value.extend_from_slice(b"; ");
    }
    value.extend_from_slice(pair);
}

impl CookieJar {
    /// Validate and retain a cookie restricted to the URL's host and HTTPS when applicable.
    #[expect(
        clippy::missing_panics_doc,
        reason = "a field value refuses only the control characters checked before construction"
    )]
    pub fn insert_for(
        &mut self,
        url: impl AsRef<str>,
        cookie: impl AsRef<str>,
    ) -> Result<(), Error> {
        let url = url::Url::parse(url.as_ref())?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(Error::CredentialedUrl(
                archivindex_http_client::prepare::redact_credentials(&url),
            ));
        }
        if url.host_str().is_none() {
            return Err(Error::MissingHost(url.to_string()));
        }
        let cookie = cookie.as_ref();
        if let Some(index) = cookie
            .bytes()
            .position(|byte| byte.is_ascii_control() && byte != b'\t')
        {
            return Err(Error::InvalidCookie {
                index,
                length: cookie.len(),
            });
        }
        let value = HeaderValue::from_str(cookie)
            .expect("a value without control characters is a field value");
        self.insert_header(&url, value);
        Ok(())
    }

    /// Combine the host's stored cookies, omitting secure cookies over HTTP.
    #[must_use]
    pub fn get(&self, url: &Url) -> Option<HeaderValue> {
        self.merged(url, Option::<&HeaderValue>::None)
    }

    /// Combine request cookies with sendable cookies stored for the host.
    ///
    /// Supplied pairs keep their order and take precedence over stored pairs of the same name.
    /// Remaining stored cookies are appended, excluding secure cookies over HTTP. Supplying one
    /// cookie therefore does not withhold clearance stored under another name.
    ///
    /// Several supplied lines are combined into the single one a request must send, as [RFC 6265
    /// section 5.4](https://www.rfc-editor.org/rfc/rfc6265#section-5.4) requires.
    #[must_use]
    pub fn merged<'a>(
        &self,
        url: &Url,
        supplied: impl IntoIterator<Item = &'a HeaderValue>,
    ) -> Option<HeaderValue> {
        let https = url.scheme() == "https";
        let mut value = Vec::new();
        let mut supplied_names = Vec::new();
        for line in supplied {
            for pair in pairs(line.as_bytes()) {
                supplied_names.push(pair_name(pair));
                extend_pairs(&mut value, pair);
            }
        }
        let held = url.host_str().and_then(|host| self.by_host.get(host));
        for cookie in held
            .into_iter()
            .flatten()
            .filter(|cookie| (https || !cookie.secure) && !supplied_names.contains(&cookie.name()))
        {
            extend_pairs(&mut value, &cookie.pair);
        }

        // The pairs came from field values, and the separator is the one the grammar uses.
        (!value.is_empty()).then(|| HeaderValue::from_bytes(&value).ok())?
    }

    /// Store cookie pairs for the host of `url`, replacing existing pairs of the same name.
    pub fn insert(&mut self, url: &Url, cookie: &StoredCookie) {
        let Some(host) = url.host_str() else {
            return;
        };
        let held = self.by_host.entry(host.to_owned()).or_default();
        for pair in pairs(cookie.value.as_bytes()) {
            let cookie = Cookie {
                pair: pair.to_vec(),
                secure: cookie.secure,
            };
            match held
                .iter_mut()
                .find(|earlier| earlier.name() == cookie.name())
            {
                Some(earlier) => *earlier = cookie,
                None => held.push(cookie),
            }
        }
    }

    /// Store supplied cookies, restricting them to HTTPS when `url` uses HTTPS.
    pub fn insert_header(&mut self, url: &Url, value: HeaderValue) {
        self.insert(
            url,
            &StoredCookie {
                value,
                secure: url.scheme() == "https",
            },
        );
    }
}

/// A cookie could not be scoped to a host, or sent as an HTTP field value.
///
/// See [`CookieJar::insert_for`].
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// The URL scoping the cookie could not be parsed.
    #[error(transparent)]
    InvalidUrl(#[from] url::ParseError),
    /// The URL scoping the cookie carries credentials. The displayed URL has them removed.
    #[error("URL contains credentials: {0}")]
    CredentialedUrl(String),
    /// The URL scoping the cookie has no host, so the cookie could not be restricted to one.
    #[error("URL has no host: {0}")]
    MissingHost(String),
    /// The cookie cannot be sent as an HTTP field value.
    ///
    /// The message says where the offending byte is, not what the value was, since a cookie may be
    /// a credential.
    #[error("invalid Cookie header value: byte {index} of {length} is a control character")]
    InvalidCookie {
        /// The offset of the first control character other than a horizontal tab.
        index: usize,
        /// The length of the value in bytes.
        length: usize,
    },
}

#[cfg(test)]
mod tests;
