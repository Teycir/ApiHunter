use crate::{
    error::CapturedError,
    http_client::{HttpClient, HttpResponse},
};
use futures::stream::{self, StreamExt};

pub struct BurstProbe {
    pub count: usize,
    pub headers: Option<Vec<(String, String)>>,
}

impl BurstProbe {
    pub fn new(count: usize, headers: Option<Vec<(String, String)>>) -> Self {
        Self { count, headers }
    }

    /// Execute concurrent burst requests.
    ///
    /// Captures owned values inside the async closures (`HttpClient` clone + owned URL)
    /// to keep this burst path robust even if execution strategy is refactored later.
    pub async fn execute(
        &self,
        client: &HttpClient,
        url: &str,
    ) -> Vec<Result<HttpResponse, CapturedError>> {
        let headers = self.headers.clone();
        let client = client.clone();
        let url = url.to_string();

        stream::iter(0..self.count)
            .map(move |_| {
                let headers = headers.clone();
                let client = client.clone();
                let url = url.clone();
                async move {
                    match headers.as_ref() {
                        Some(h) => client.get_with_headers_burst(&url, h).await,
                        None => client.get_burst(&url).await,
                    }
                }
            })
            .buffer_unordered(self.count.max(1))
            .collect()
            .await
    }
}
