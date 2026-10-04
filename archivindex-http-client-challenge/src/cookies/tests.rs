use http::header::HeaderValue;
use url::Url;

use super::{CookieJar, StoredCookie};

fn url(scheme: &str) -> Url {
    Url::parse(&format!("{scheme}://example.com/path")).expect("a URL")
}

fn issued(value: &'static str, secure: bool) -> StoredCookie {
    StoredCookie {
        value: HeaderValue::from_static(value),
        secure,
    }
}

#[test]
fn a_challenge_cookie_joins_a_supplied_one() {
    let mut jar = CookieJar::default();
    jar.insert_header(&url("http"), HeaderValue::from_static("session=1"));
    jar.insert(&url("http"), &issued("clearance=2", false));

    assert_eq!(
        jar.get(&url("http")),
        Some("session=1; clearance=2".parse().expect("a value"))
    );
}

#[test]
fn a_cookie_of_the_same_name_is_replaced_in_place() {
    let mut jar = CookieJar::default();
    jar.insert(&url("http"), &issued("pow_trace=a; pow_bypass=b", false));
    jar.insert(&url("http"), &issued("pow_trace=c", false));

    assert_eq!(
        jar.get(&url("http")),
        Some("pow_trace=c; pow_bypass=b".parse().expect("a value"))
    );
}

#[test]
fn a_secure_cookie_is_withheld_from_http() {
    let mut jar = CookieJar::default();
    jar.insert_header(&url("https"), HeaderValue::from_static("session=1"));
    jar.insert(&url("http"), &issued("clearance=2", false));

    assert_eq!(
        jar.get(&url("http")),
        Some("clearance=2".parse().expect("a value"))
    );
    assert_eq!(
        jar.get(&url("https")),
        Some("session=1; clearance=2".parse().expect("a value"))
    );
}

#[test]
fn a_host_holding_nothing_sendable_gets_no_field() {
    let mut jar = CookieJar::default();
    jar.insert_header(&url("https"), HeaderValue::from_static("session=1"));

    assert_eq!(jar.get(&url("http")), None);
    assert_eq!(
        jar.get(&Url::parse("http://other.example/").expect("a URL")),
        None
    );
}
