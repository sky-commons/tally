//! Reading readsb and the relay over loopback HTTP: one GET, bounded in time and in size.

use std::time::Duration;

use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Bytes;
use hyper::{StatusCode, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

/// The longest one read of readsb or the relay may take, connection included.
pub const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// The most one answer may hold: readsb's whole world with positions is a few megabytes.
pub const UPSTREAM_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone)]
pub struct Upstream {
    client: Client<HttpConnector, Empty<Bytes>>,
}

impl Default for Upstream {
    fn default() -> Self {
        Self::new()
    }
}

impl Upstream {
    pub fn new() -> Self {
        Self {
            client: Client::builder(TokioExecutor::new()).build_http(),
        }
    }

    /// The body of a 200 answer to `GET url`.
    pub async fn get(&self, url: &str) -> Result<Bytes, String> {
        let uri: Uri = url.parse().map_err(|error| format!("{url}: {error}"))?;
        let read = async {
            let response = self
                .client
                .get(uri)
                .await
                .map_err(|error| format!("{url}: {error}"))?;
            if response.status() != StatusCode::OK {
                return Err(format!("{url}: {}", response.status()));
            }
            let body = Limited::new(response.into_body(), UPSTREAM_BYTES)
                .collect()
                .await
                .map_err(|error| format!("{url}: {error}"))?;
            Ok(body.to_bytes())
        };
        tokio::time::timeout(UPSTREAM_TIMEOUT, read)
            .await
            .map_err(|_| format!("{url}: no answer in {UPSTREAM_TIMEOUT:?}"))?
    }
}
