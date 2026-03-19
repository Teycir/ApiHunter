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

    pub async fn execute(
        &self,
        client: &HttpClient,
        url: &str,
    ) -> Vec<Result<HttpResponse, CapturedError>> {
        let headers = self.headers.clone();

        stream::iter(0..self.count)
            .map(|_| {
                let headers = headers.clone();
                async move {
                    match headers.as_ref() {
                        Some(h) => client.get_with_headers_burst(url, h).await,
                        None => client.get_burst(url).await,
                    }
                }
            })
            .buffer_unordered(self.count.max(1))
            .collect()
            .await
    }
}
