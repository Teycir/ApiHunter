use crate::{
    error::CapturedError,
    http_client::{HttpClient, HttpResponse},
};

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
        let mut results = Vec::with_capacity(self.count);

        for _ in 0..self.count {
            let result = match &self.headers {
                Some(h) => client.get_with_headers(url, h).await,
                None => client.get(url).await,
            };
            results.push(result);
        }

        results
    }
}
