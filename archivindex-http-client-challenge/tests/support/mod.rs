use std::time::Duration;

use archivindex_http_client::message::ResponseMetadata;
use archivindex_http_client::reconstruct::{reconstruct_request, reconstruct_response};
use archivindex_http_client::{CapturedExchange, Fidelity, HttpProtocol};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Version};

pub const TOKEN: &str = "021c7f24e8c1ed8c4472a22aa9b441b223a08cb15fa889293574500e190960dc";
pub const NONCE: &str = "83462578e314e3b20855f1cb32d30a09";
pub const TRACE_NONCE: &str = "e71e658fa0f38f0361551e676842c933";
pub const ISSUED_AT: &str = "1787485140";

pub fn captured(url: &str, status: u16, fields: &[(&str, &str)], body: &[u8]) -> CapturedExchange {
    let mut headers = HeaderMap::new();
    for &(name, value) in fields {
        headers.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    let response = reconstruct_response(
        Version::HTTP_11,
        StatusCode::from_u16(status).unwrap(),
        &headers,
        Some(body),
    )
    .unwrap();
    CapturedExchange {
        request: reconstruct_request(
            &Method::GET,
            &url.parse().unwrap(),
            Version::HTTP_11,
            &HeaderMap::new(),
            None,
        ),
        response_metadata: ResponseMetadata::parse(&response).unwrap(),
        response,
        fidelity: Fidelity::Reconstructed,
        http_protocol: HttpProtocol::Http1,
        tls_version: None,
        target_uri: url.to_owned().parse().unwrap(),
        ip_address: None,
        date: chrono::Utc::now(),
        fetch_time: Duration::ZERO,
        truncated: None,
    }
}

pub fn sucuri_body(secure: bool) -> String {
    let secure = if secure { ";Secure" } else { "" };
    let script = format!(
        "v='cookie-value';document.cookie='sucuri_cloudproxy_uuid_test=' + v + \
         ';path=/;max-age=86400;SameSite=Lax{secure}'; location.reload();"
    );
    let encoded = data_encoding::BASE64.encode(script.as_bytes());
    format!("<html><script>var sucuri_cloudproxy_js='',S='{encoded}';</script></html>")
}

pub fn simply_body(path: &str, difficulty: u32) -> String {
    format!(
        "<html><script>var T=\"{TOKEN}\",TS=\"{ISSUED_AT}\",D={difficulty};\
         x.open(\"POST\",\"{path}\");</script></html>"
    )
}

pub fn varnish_body(domain: &str) -> String {
    format!(
        "<script>window.POW_CHALLENGE_DATA={{\
         challenge_nonce:'{NONCE}',challenge_hmac:'22d6f9feb179b6b7e9616ede',\
         difficulty:'1',difficulty_char:'b',issued_at:'{ISSUED_AT}',\
         cookie_duration:'3600',cookie_domain:'{domain}'}};</script>"
    )
}
