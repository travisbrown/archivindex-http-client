//! Request preparation and redirect policy extracted from the WARC client.
use std::borrow::Cow;

use archivindex_http_client::conditional::{Validators, request_field};
use archivindex_http_client::prepare::{request_target, target};
use archivindex_http_client::redirect::{next_location, redirect_request};
use fluent_uri::Uri;
use http::header::{ACCEPT_LANGUAGE, CONTENT_TYPE, COOKIE, HOST, USER_AGENT};
use http::{HeaderMap, HeaderValue, Method};
use url::Url;

#[test]
fn request_targets_are_valid_uris() {
    let url = Url::parse("http://example.com/a|b^c[d]?x={y}`z#frag").expect("valid URL");
    let target = request_target(&url);
    assert_eq!(target, "http://example.com/a%7Cb%5Ec%5Bd%5D?x=%7By%7D%60z");
    assert!(Uri::parse(target.as_ref()).is_ok());
}

/// A selecting field sent as several lines resolves to their combined value, as the recorded
/// request resolves it, so that a `Cookie` given as two lines still selects a variant.
#[test]
fn request_fields_resolve_as_combined_values() {
    let mut headers = HeaderMap::new();
    headers.append(ACCEPT_LANGUAGE, HeaderValue::from_static("en"));
    headers.append(ACCEPT_LANGUAGE, HeaderValue::from_static("de"));
    headers.insert(USER_AGENT, HeaderValue::from_static("Bot/1.0"));
    headers.append(COOKIE, HeaderValue::from_static("configured=1"));
    headers.append(COOKIE, HeaderValue::from_static("clearance=2"));

    assert_eq!(
        request_field(&headers, "accept-language"),
        Some(Cow::Owned("en, de".to_owned()))
    );
    assert_eq!(
        request_field(&headers, "user-agent"),
        Some(Cow::Borrowed("Bot/1.0"))
    );
    assert_eq!(request_field(&headers, "accept"), None);
    assert_eq!(
        request_field(&headers, "cookie"),
        Some(Cow::Owned("configured=1, clearance=2".to_owned()))
    );
}

/// A redirect within one origin keeps the authority-specific fields a caller set, and one to
/// another origin does not.
#[test]
fn a_host_override_survives_a_same_origin_redirect() {
    let current = Url::parse("http://10.0.0.5/one").expect("valid URL");
    let mut method = Method::GET;
    let mut body = None;
    let mut headers = HeaderMap::new();
    headers.insert(HOST, HeaderValue::from_static("example.com"));
    headers.insert(COOKIE, HeaderValue::from_static("session=1"));

    let next = Url::parse("http://10.0.0.5/two").expect("valid URL");
    redirect_request(&current, &next, 302, &mut method, &mut headers, &mut body);
    assert_eq!(
        headers.get(HOST),
        Some(&HeaderValue::from_static("example.com"))
    );
    assert_eq!(
        headers.get(COOKIE),
        Some(&HeaderValue::from_static("session=1"))
    );

    let next = Url::parse("http://10.0.0.6/two").expect("valid URL");
    redirect_request(&current, &next, 302, &mut method, &mut headers, &mut body);
    assert_eq!(headers.get(HOST), None);
    assert_eq!(headers.get(COOKIE), None);
}

/// A `POST` redirected by a `303` becomes a bodiless `GET`, and a `307` preserves it.
#[test]
fn a_redirect_rewrites_the_method_as_user_agents_do() {
    let current = Url::parse("http://example.com/one").expect("valid URL");
    let next = Url::parse("http://example.com/two").expect("valid URL");

    let mut method = Method::POST;
    let mut body = Some(b"a=1".to_vec());
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    redirect_request(&current, &next, 307, &mut method, &mut headers, &mut body);
    assert_eq!(method, Method::POST);
    assert_eq!(body.as_deref(), Some(&b"a=1"[..]));

    redirect_request(&current, &next, 303, &mut method, &mut headers, &mut body);
    assert_eq!(method, Method::GET);
    assert_eq!(body, None);
    assert_eq!(headers.get(CONTENT_TYPE), None);
}

#[test]
fn plain_request_targets_are_borrowed() {
    let url = Url::parse("http://example.com/a?b=c#frag").expect("valid URL");
    assert!(matches!(
        request_target(&url),
        Cow::Borrowed("http://example.com/a?b=c")
    ));
}

#[test]
fn invalid_or_credentialed_redirects_are_not_followed() {
    let current = Url::parse("https://example.com/start").unwrap();
    for location in ["data:text/plain,body", "http://user:secret@example.com/"] {
        assert!(next_location(&current, 302, Some(location)).is_none());
    }
    assert!(next_location(&current, 304, Some("/next")).is_none());
    assert_eq!(
        next_location(&current, 308, Some("/next"))
            .unwrap()
            .as_str(),
        "https://example.com/next"
    );
    let error = target(&Url::parse("https://user:secret@example.com/").unwrap()).unwrap_err();
    assert!(!error.to_string().contains("secret"));
    assert!(target(&Url::parse("data:text/plain,body").unwrap()).is_err());
}

#[test]
fn validators_ignore_invalid_fields_and_replace_existing_conditions() {
    let validators =
        Validators::new(Some("bad\r\nfield"), Some("Wed, 21 Oct 2015 07:28:00 GMT")).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("if-modified-since", HeaderValue::from_static("old"));
    validators.apply(&mut headers);
    assert!(!headers.contains_key("if-none-match"));
    assert_eq!(
        headers["if-modified-since"],
        "Wed, 21 Oct 2015 07:28:00 GMT"
    );
    assert!(Validators::new(None, Some("invalid\nfield")).is_none());
}
