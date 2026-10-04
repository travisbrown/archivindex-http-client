//! The request most client tests make.

use std::sync::LazyLock;

use archivindex_http_client::Request;
use http::{HeaderMap, Method, Uri};

static GET: Method = Method::GET;
static NO_HEADERS: LazyLock<HeaderMap> = LazyLock::new(HeaderMap::new);

/// A `GET` request for `target` without optional headers or a body.
pub fn get(target: &Uri) -> Request<'_> {
    Request {
        method: &GET,
        target,
        headers: &NO_HEADERS,
        body: None,
    }
}
