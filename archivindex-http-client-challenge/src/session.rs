use std::convert::Infallible;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use archivindex_http_client::prepare::target;
use archivindex_http_client::redirect::{next_location, redirect_request};
use archivindex_http_client::{CapturedExchange, Client, Request};
use http::header::{
    ACCEPT_ENCODING, ACCEPT_LANGUAGE, AUTHORIZATION, CONTENT_TYPE, COOKIE, HOST, HeaderValue,
    PROXY_AUTHORIZATION, USER_AGENT,
};
use http::{HeaderMap, Method};
use url::Url;

use crate::cookies::CookieJar;
use crate::{
    Challenge, Error, FetchError, MAX_CHALLENGE_ANSWERS, Observer, ProofOfWork, RequestKind,
    Session, recognize,
};

impl<C: Client> Session<C> {
    /// Start a session with an empty cookie jar and no redirect following.
    pub fn new(client: C) -> Self {
        Self {
            client,
            cookies: Arc::default(),
            max_redirects: 0,
        }
    }

    /// Share clearance with other sessions. The jar is locked only while reading or updating it.
    #[must_use]
    pub fn with_cookies(mut self, cookies: Arc<Mutex<CookieJar>>) -> Self {
        self.cookies = cookies;
        self
    }

    /// Follow at most this many redirects, sharing one deadline and challenge budget.
    #[must_use]
    pub const fn max_redirects(mut self, maximum: usize) -> Self {
        self.max_redirects = maximum;
        self
    }

    /// Access retained cookies. Release the guard before fetching through this or another session.
    ///
    /// Poisoned locks retain the jar, since internal critical sections only read or update cookies.
    pub fn cookies(&self) -> MutexGuard<'_, CookieJar> {
        self.cookies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Fetch and return every completed exchange, including redirects and verification requests.
    pub fn fetch(&self, request: Request<'_>) -> Result<Vec<CapturedExchange>, Error> {
        self.fetch_within(request, None)
    }

    /// Fetch before one deadline for the entire sequence.
    pub fn fetch_by(
        &self,
        request: Request<'_>,
        deadline: Instant,
    ) -> Result<Vec<CapturedExchange>, Error> {
        self.fetch_within(request, Some(deadline))
    }

    /// Fetch with an optional overall deadline, retaining completed exchanges on failure.
    pub fn fetch_within(
        &self,
        request: Request<'_>,
        deadline: Option<Instant>,
    ) -> Result<Vec<CapturedExchange>, Error> {
        let mut collector = Collector(Vec::new());
        match self.fetch_with(request, deadline, &mut collector) {
            Ok(_) => Ok(collector.0),
            Err(FetchError::Client(source)) => Err(Error {
                exchanges: collector.0,
                source,
            }),
            Err(FetchError::Observer(never)) => match never {},
        }
    }

    /// Fetch with request preparation and exchange observation supplied by the caller.
    ///
    /// Cookies and a missing `Accept-Encoding: identity` are resolved before preparation. Each
    /// prepared exchange is observed exactly once before another request is attempted. No cookie
    /// lock is held during callbacks or network activity. The return value counts followed redirects.
    /// Verification requests are marked separately so callers can omit representation validators.
    pub fn fetch_with<O: Observer>(
        &self,
        request: Request<'_>,
        deadline: Option<Instant>,
        observer: &mut O,
    ) -> Result<usize, FetchError<O::Error>> {
        if !matches!(request.target.scheme_str(), Some("http" | "https")) {
            return Err(archivindex_http_client::Error::UnsupportedScheme.into());
        }
        let mut current = Url::parse(&request.target.to_string())
            .map_err(archivindex_http_client::prepare::Error::from)
            .map_err(archivindex_http_client::Error::from)?;
        let mut method = request.method.clone();
        let mut headers = request.headers.clone();
        let mut body = request.body.map(<[u8]>::to_vec);
        let mut redirects = 0;
        let mut answered = 0;
        loop {
            let target = target(&current).map_err(archivindex_http_client::Error::from)?;
            let captured = self.fetch_one(
                Request {
                    method: &method,
                    target: &target,
                    headers: &headers,
                    body: body.as_deref(),
                },
                RequestKind::Resource,
                deadline,
                observer,
            )?;
            let status = captured.response_metadata.status;
            let next = next_location(
                &current,
                status,
                captured
                    .response_metadata
                    .header("location")
                    .and_then(|value| std::str::from_utf8(value).ok()),
            );
            let can_answer =
                next.is_none() && answered < MAX_CHALLENGE_ANSWERS && captured.truncated.is_none();
            let challenge = can_answer.then(|| recognize(&captured, deadline)).flatten();
            observer.captured(captured, &method);
            if can_answer {
                check_deadline(deadline)?;
            }
            match next {
                Some(next) if redirects < self.max_redirects => {
                    redirects += 1;
                    redirect_request(
                        &current,
                        &next,
                        status,
                        &mut method,
                        &mut headers,
                        &mut body,
                    );
                    current = next;
                }
                Some(_) => return Ok(redirects),
                None => {
                    let Some(challenge) = challenge else {
                        return Ok(redirects);
                    };
                    let cookie = match challenge {
                        Challenge::Cookie(cookie) => Some(cookie),
                        Challenge::ProofOfWork(proof) => {
                            let captured = self.submit(&proof, &headers, deadline, observer)?;
                            let cookie = proof.clearance_cookie(&captured);
                            observer.captured(captured, &Method::POST);
                            cookie
                        }
                    };
                    let Some(cookie) = cookie else {
                        return Ok(redirects);
                    };
                    self.cookies().insert(&current, &cookie);
                    answered += 1;
                }
            }
        }
    }

    fn fetch_one<O: Observer>(
        &self,
        request: Request<'_>,
        kind: RequestKind,
        deadline: Option<Instant>,
        observer: &mut O,
    ) -> Result<CapturedExchange, FetchError<O::Error>> {
        check_deadline(deadline)?;
        let url = Url::parse(&request.target.to_string())
            .map_err(archivindex_http_client::prepare::Error::from)
            .map_err(archivindex_http_client::Error::from)?;
        let mut headers = request.headers.clone();
        headers
            .entry(ACCEPT_ENCODING)
            .or_insert(HeaderValue::from_static("identity"));
        let cookie = self.cookies().merged(&url, headers.get_all(COOKIE));
        if let Some(cookie) = cookie {
            headers.insert(COOKIE, cookie);
        }
        observer
            .prepare(request.method, request.target, &mut headers, kind)
            .map_err(FetchError::Observer)?;
        self.client
            .fetch_within(
                Request {
                    headers: &headers,
                    ..request
                },
                deadline,
            )
            .map_err(FetchError::Client)
    }

    fn submit<O: Observer>(
        &self,
        proof: &ProofOfWork,
        original_headers: &HeaderMap,
        deadline: Option<Instant>,
        observer: &mut O,
    ) -> Result<CapturedExchange, FetchError<O::Error>> {
        let target =
            target(proof.verification_url()).map_err(archivindex_http_client::Error::from)?;
        let mut headers = HeaderMap::new();
        // Preserve identity on this same-origin request. Body metadata, validators, and ranges
        // belong to the resource request rather than proof verification.
        for name in [
            USER_AGENT,
            ACCEPT_LANGUAGE,
            AUTHORIZATION,
            PROXY_AUTHORIZATION,
            HOST,
            COOKIE,
        ] {
            for value in original_headers.get_all(&name) {
                headers.append(name.clone(), value.clone());
            }
        }
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        let body = proof.request_body();
        self.fetch_one(
            Request {
                method: &Method::POST,
                target: &target,
                headers: &headers,
                body: Some(body.as_bytes()),
            },
            RequestKind::Verification,
            deadline,
            observer,
        )
    }
}

struct Collector(Vec<CapturedExchange>);

impl Observer for Collector {
    type Error = Infallible;

    fn prepare(
        &mut self,
        _: &Method,
        _: &http::Uri,
        _: &mut HeaderMap,
        _: RequestKind,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn captured(&mut self, exchange: CapturedExchange, _: &Method) {
        self.0.push(exchange);
    }
}

fn check_deadline(deadline: Option<Instant>) -> Result<(), archivindex_http_client::Error> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "challenge session deadline elapsed",
        )
        .into())
    } else {
        Ok(())
    }
}
