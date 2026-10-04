//! HTTP validators and selection of representations declared by Vary.

use std::borrow::Cow;

use crate::message::ResponseMetadata;

/// Read the `Vary` field of a recorded response, combining its lines as a recipient does.
///
/// A server may send `Vary` as several field lines, which a recipient combines into one
/// comma-separated value (RFC 9110 section 5.3). Reading only the first line would drop the
/// selecting fields the later lines name, so a request differing in one of them would be taken to
/// select the stored representation and could reuse validators describing other bytes.
///
/// A line that is not readable as text names no field a later request could be matched against, so
/// the value becomes `*`, leaving the representation [`Unselectable`](Variance::Unselectable)
/// rather than silently narrowing what the server declared.
///
/// The result is the `vary` argument of [`Variance::declared`] and
/// [`Variance::declared_without_request`]; `None` means the response declared no `Vary` at all.
#[must_use]
pub fn declared_vary(metadata: &ResponseMetadata) -> Option<String> {
    metadata.headers("vary").next()?;

    Some(
        metadata
            .combined_header("vary")
            .map_or_else(|| Variance::UNSELECTABLE.to_owned(), Cow::into_owned),
    )
}

/// What a stored response declared about the request fields that select its representation.
///
/// HTTP allows one URI to have several representations chosen by request header fields, which a
/// response announces in `Vary`. Stored validators belong to the representation that was actually
/// captured, so a later request may reuse them only when it selects that same representation.
/// Without the check, a crawl configured with a different `User-Agent` could revalidate against
/// another variant's `ETag` and accept a `304 Not Modified` for a representation it never received.
///
/// A response that declares no `Vary` is treated as invariant, as an HTTP cache treats it: a server
/// that varies its representations without saying so is indistinguishable from one that does not
/// vary at all.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum Variance {
    /// The response declared no `Vary` field, so every request for the URI selects it.
    #[default]
    Invariant,
    /// The stored representation cannot be selected by request header fields.
    ///
    /// Either the response declared `Vary: *`, or it named selecting fields whose values in the
    /// originating request are unknown. Neither can be matched, so state stored under this variance
    /// is never reused for revalidation.
    Unselectable,
    /// The response named selecting fields, recorded with the originating request's values.
    Selected(SelectingHeaders),
}

impl Variance {
    /// The `Vary` wildcard that prevents selection by request fields.
    const UNSELECTABLE: &'static str = "*";

    /// Record the variance a response declared, resolved against the request that produced it.
    ///
    /// `vary` is the response's `Vary` field value, absent when the response declares none. `field`
    /// returns the request's value for a lowercase field name, or `None` when the request sent no
    /// such field; a field that was not sent is distinct from one sent empty. A field sent as
    /// several lines is resolved as their combined value (RFC 9110 section 5.3), which is what RFC
    /// 9111 section 4.1 compares between requests. That section also permits normalizing white
    /// space and list order. This model compares values as sent, which may prevent reuse but cannot
    /// select the wrong representation.
    ///
    /// Values containing line breaks yield [`Variance::Unselectable`]. Callers must unfold recorded
    /// header values before passing them here.
    #[must_use]
    pub fn declared<V: AsRef<str>>(
        vary: Option<&str>,
        mut field: impl FnMut(&str) -> Option<V>,
    ) -> Self {
        let Some(vary) = vary else {
            return Self::Invariant;
        };
        let mut entries = Vec::new();

        for name in vary.split(',') {
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            if name == Self::UNSELECTABLE {
                return Self::Unselectable;
            }
            let name = name.to_ascii_lowercase();
            let value = field(&name);
            let value = value.as_ref().map(AsRef::as_ref);
            if name.contains(['\r', '\n'])
                || value.is_some_and(|value| value.contains(['\r', '\n']))
            {
                return Self::Unselectable;
            }
            entries.push((name.into_boxed_str(), value.map(Box::from)));
        }

        if entries.is_empty() {
            return Self::Invariant;
        }
        entries.sort_by(|(left, _), (right, _)| left.cmp(right));
        entries.dedup_by(|(left, _), (right, _)| left == right);

        Self::Selected(SelectingHeaders { entries })
    }

    /// Record the variance a response declared when the originating request is unavailable.
    ///
    /// A response naming selecting fields becomes [`Variance::Unselectable`]: with no record of the
    /// request that produced it, there is nothing for a later request to match. State recovered
    /// this way therefore supports revalidation only when its response declared no `Vary`.
    #[must_use]
    pub fn declared_without_request(vary: Option<&str>) -> Self {
        match vary {
            Some(vary) if vary.split(',').any(|name| !name.trim().is_empty()) => Self::Unselectable,
            _ => Self::Invariant,
        }
    }

    /// Whether a request selects the representation this state was stored for.
    ///
    /// Validators must not be sent for a request this returns `false` for: the server would answer
    /// about a representation other than the one the request selects.
    ///
    /// `field` follows the same contract as in [`Variance::declared`].
    #[must_use]
    pub fn matches<V: AsRef<str>>(&self, mut field: impl FnMut(&str) -> Option<V>) -> bool {
        match self {
            Self::Invariant => true,
            Self::Unselectable => false,
            Self::Selected(headers) => headers
                .entries
                .iter()
                .all(|(name, value)| field(name).as_ref().map(AsRef::as_ref) == value.as_deref()),
        }
    }
}

/// The values a request carried for the fields a response named in `Vary`.
///
/// Names are lowercased and sorted, so one selection compares equal to another regardless of the
/// order or case the server wrote its `Vary` field in.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectingHeaders {
    entries: Vec<(Box<str>, Option<Box<str>>)>,
}

impl SelectingHeaders {
    /// Restore stored selecting fields. Names must already be lowercase, sorted, and unique.
    #[must_use]
    pub const fn from_entries(entries: Vec<(Box<str>, Option<Box<str>>)>) -> Self {
        Self { entries }
    }

    /// Iterate over normalized field names and their original values, including absent fields.
    pub fn iter(&self) -> impl Iterator<Item = (&str, Option<&str>)> {
        self.entries
            .iter()
            .map(|(name, value)| (name.as_ref(), value.as_deref()))
    }
}

/// Resolve a request field as a combined value, or as absent when unreadable.
#[must_use]
pub fn request_field<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<Cow<'a, str>> {
    crate::message::combined_field(
        headers
            .get_all(name)
            .iter()
            .map(http::HeaderValue::as_bytes),
    )
}

/// Validators of a previously obtained representation.
#[derive(Clone, Debug, Default)]
pub struct Validators {
    etag: Option<http::HeaderValue>,
    last_modified: Option<http::HeaderValue>,
}

impl Validators {
    /// Parse usable validators, ignoring values that cannot be sent as header fields.
    #[must_use]
    pub fn new(etag: Option<&str>, last_modified: Option<&str>) -> Option<Self> {
        let etag = etag.and_then(|value| http::HeaderValue::from_str(value).ok());
        let last_modified = last_modified.and_then(|value| http::HeaderValue::from_str(value).ok());
        (etag.is_some() || last_modified.is_some()).then_some(Self {
            etag,
            last_modified,
        })
    }

    /// Add conditional fields, replacing any caller-supplied value of the same name.
    pub fn apply(&self, headers: &mut http::HeaderMap) {
        if let Some(etag) = &self.etag {
            headers.insert(http::header::IF_NONE_MATCH, etag.clone());
        }
        if let Some(modified) = &self.last_modified {
            headers.insert(http::header::IF_MODIFIED_SINCE, modified.clone());
        }
    }
}

#[cfg(test)]
mod tests;
