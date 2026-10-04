use std::time::{Duration, Instant};

use archivindex_http_client::Error;
use archivindex_http_client::framing::Truncation;
use archivindex_http_client_challenge::{MAX_CHALLENGE_ANSWERS, Session};
use http::HeaderMap;

use super::{Scripted, TARGET, VERIFY, captured, request, simply, sucuri};

#[test]
fn repeated_challenges_stop_at_the_answer_limit() {
    let client = Scripted::new((0..=MAX_CHALLENGE_ANSWERS).map(|_| Ok(sucuri())));
    let exchanges = Session::new(client.clone())
        .fetch(request(&TARGET.parse().unwrap(), &HeaderMap::new()))
        .unwrap();
    assert_eq!(exchanges.len(), MAX_CHALLENGE_ANSWERS + 1);
    client.assert_finished();
}

#[test]
fn refused_and_truncated_verification_responses_are_retained_without_retrying() {
    let rejected = captured(VERIFY, 403, &[], b"refused");
    let mut truncated = captured(VERIFY, 200, &[], br#"{"ok":true,"cookie":"clearance"}"#);
    truncated.truncated = Some(Truncation::Disconnect);
    for response in [rejected, truncated] {
        let client = Scripted::new([Ok(simply()), Ok(response.clone())]);
        let session = Session::new(client.clone());
        let exchanges = session
            .fetch(request(&TARGET.parse().unwrap(), &HeaderMap::new()))
            .unwrap();
        assert_eq!(exchanges.len(), 2);
        assert_eq!(exchanges[1].response, response.response);
        assert_eq!(exchanges[1].truncated, response.truncated);
        assert!(session.cookies().get(&TARGET.parse().unwrap()).is_none());
        client.assert_finished();
    }
}

#[test]
fn transport_errors_retain_challenges_and_successful_verification() {
    for before_failure in [
        vec![],
        vec![sucuri()],
        vec![simply()],
        vec![
            simply(),
            captured(VERIFY, 200, &[], br#"{"ok":true,"cookie":"clearance"}"#),
        ],
    ] {
        let expected: Vec<_> = before_failure
            .iter()
            .map(|exchange| exchange.response.clone())
            .collect();
        let responses = before_failure
            .into_iter()
            .map(Ok)
            .chain([Err(std::io::Error::from(
                std::io::ErrorKind::ConnectionReset,
            )
            .into())]);
        let client = Scripted::new(responses);
        let error = Session::new(client.clone())
            .fetch(request(&TARGET.parse().unwrap(), &HeaderMap::new()))
            .unwrap_err();
        assert!(
            matches!(error.source, Error::Io(error) if error.kind() == std::io::ErrorKind::ConnectionReset)
        );
        assert_eq!(
            error
                .exchanges
                .into_iter()
                .map(|exchange| exchange.response)
                .collect::<Vec<_>>(),
            expected
        );
        client.assert_finished();
    }
}

#[test]
fn expired_deadlines_prevent_requests_and_preserve_already_captured_responses() {
    let client = Scripted::new([]);
    let error = Session::new(client.clone())
        .fetch_by(
            request(&TARGET.parse().unwrap(), &HeaderMap::new()),
            Instant::now(),
        )
        .unwrap_err();
    assert_eq!(error.exchanges, []);
    assert!(
        matches!(error.source, Error::Io(error) if error.kind() == std::io::ErrorKind::TimedOut)
    );
    client.assert_finished();

    for truncated in [None, Some(Truncation::Time)] {
        let mut response = sucuri();
        response.truncated = truncated;
        let client = Scripted::new([Ok(response.clone())]).expire_deadline();
        let outcome = Session::new(client.clone()).fetch_by(
            request(&TARGET.parse().unwrap(), &HeaderMap::new()),
            Instant::now() + Duration::from_millis(20),
        );
        let exchanges = if truncated.is_some() {
            outcome.unwrap()
        } else {
            let error = outcome.unwrap_err();
            assert!(
                matches!(error.source, Error::Io(error) if error.kind() == std::io::ErrorKind::TimedOut)
            );
            error.exchanges
        };
        assert_eq!(exchanges.len(), 1);
        assert_eq!(exchanges[0].response, response.response);
        assert_eq!(exchanges[0].truncated, truncated);
        client.assert_finished();
    }
}

#[test]
fn ordinary_redirects_and_truncated_challenges_end_the_sequence() {
    let mut truncated = sucuri();
    truncated.truncated = Some(Truncation::Length);
    for response in [
        captured(TARGET, 302, &[("location", "/next")], b"redirect"),
        captured(TARGET, 454, &[], b"unrecognized challenge"),
        truncated,
    ] {
        let client = Scripted::new([Ok(response.clone())]);
        let exchanges = Session::new(client.clone())
            .fetch(request(&TARGET.parse().unwrap(), &HeaderMap::new()))
            .unwrap();
        assert_eq!(exchanges.len(), 1);
        assert_eq!(exchanges[0].response, response.response);
        client.assert_finished();
    }
}
