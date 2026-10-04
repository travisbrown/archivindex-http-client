use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use archivindex_http_client::reconstruct::reconstruct_request;
use archivindex_http_client::{CapturedExchange, Client, Error, Request};
use http::{HeaderMap, Method, Uri, Version};

#[derive(Clone, Debug)]
pub struct SentRequest {
    pub method: Method,
    pub target: Uri,
    pub headers: HeaderMap,
    pub body: Option<Vec<u8>>,
    pub deadline: Option<Instant>,
}

#[derive(Debug)]
struct State {
    replies: VecDeque<Result<CapturedExchange, Error>>,
    sent: Vec<SentRequest>,
}

#[derive(Clone, Debug)]
pub struct Scripted {
    state: Arc<Mutex<State>>,
    expire_deadline: bool,
}

impl Scripted {
    pub fn new(replies: impl IntoIterator<Item = Result<CapturedExchange, Error>>) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                replies: replies.into_iter().collect(),
                sent: Vec::new(),
            })),
            expire_deadline: false,
        }
    }

    pub const fn expire_deadline(mut self) -> Self {
        self.expire_deadline = true;
        self
    }

    pub fn sent(&self) -> Vec<SentRequest> {
        self.state.lock().unwrap().sent.clone()
    }

    pub fn assert_finished(&self) {
        assert!(self.state.lock().unwrap().replies.is_empty());
    }
}

impl Client for Scripted {
    fn fetch_within(
        &self,
        request: Request<'_>,
        deadline: Option<Instant>,
    ) -> Result<CapturedExchange, Error> {
        if self.expire_deadline {
            std::thread::sleep(deadline.unwrap().saturating_duration_since(Instant::now()));
        }
        let mut state = self.state.lock().unwrap();
        state.sent.push(SentRequest {
            method: request.method.clone(),
            target: request.target.clone(),
            headers: request.headers.clone(),
            body: request.body.map(<[u8]>::to_vec),
            deadline,
        });
        let mut captured = state.replies.pop_front().expect("an expected request")?;
        drop(state);
        assert_eq!(captured.target_uri.as_str(), request.target.to_string());
        captured.request = reconstruct_request(
            request.method,
            request.target,
            Version::HTTP_11,
            request.headers,
            request.body,
        );
        Ok(captured)
    }
}
