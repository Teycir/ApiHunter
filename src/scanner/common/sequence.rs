use reqwest::{header::HeaderMap, Method};

use crate::{
    error::CapturedError,
    http_client::{HttpClient, HttpResponse},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceActor {
    Primary,
    Secondary,
    Unauthenticated,
}

#[derive(Debug, Clone)]
pub struct SequenceStep {
    pub name: String,
    pub actor: SequenceActor,
    pub method: Method,
    pub url: String,
    pub body: Option<serde_json::Value>,
    pub headers: Vec<(String, String)>,
}

impl SequenceStep {
    pub fn new(
        name: impl Into<String>,
        actor: SequenceActor,
        method: Method,
        url: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            actor,
            method,
            url: url.into(),
            body: None,
            headers: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_json_body(mut self, body: serde_json::Value) -> Self {
        self.body = Some(body);
        self
    }

    #[must_use]
    pub fn with_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.headers = headers;
        self
    }
}

#[derive(Debug, Clone)]
pub struct SequenceStepResult {
    pub name: String,
    pub actor: SequenceActor,
    pub url: String,
    pub status: Option<u16>,
    pub response: Option<HttpResponse>,
}

pub struct SequenceRunner<'a> {
    primary: &'a HttpClient,
    secondary: Option<&'a HttpClient>,
}

impl<'a> SequenceRunner<'a> {
    pub fn new(primary: &'a HttpClient, secondary: Option<&'a HttpClient>) -> Self {
        Self { primary, secondary }
    }

    pub async fn run(
        &self,
        steps: &[SequenceStep],
    ) -> (Vec<SequenceStepResult>, Vec<CapturedError>) {
        let mut results = Vec::with_capacity(steps.len());
        let mut errors = Vec::new();

        for step in steps {
            match self.execute_step(step).await {
                Ok(response) => results.push(SequenceStepResult {
                    name: step.name.clone(),
                    actor: step.actor,
                    url: step.url.clone(),
                    status: Some(response.status),
                    response: Some(response),
                }),
                Err(err) => {
                    errors.push(err);
                    results.push(SequenceStepResult {
                        name: step.name.clone(),
                        actor: step.actor,
                        url: step.url.clone(),
                        status: None,
                        response: None,
                    });
                }
            }
        }

        (results, errors)
    }

    async fn execute_step(&self, step: &SequenceStep) -> Result<HttpResponse, CapturedError> {
        match step.actor {
            SequenceActor::Primary => {
                let headers = build_header_map(&step.headers);
                self.primary
                    .request(step.method.clone(), &step.url, headers, step.body.clone())
                    .await
            }
            SequenceActor::Secondary => {
                let Some(secondary) = self.secondary else {
                    return Err(CapturedError::from_str(
                        "sequence/secondary-missing",
                        Some(step.url.clone()),
                        format!("Sequence step '{}' requested secondary actor", step.name),
                    ));
                };
                let headers = build_header_map(&step.headers);
                secondary
                    .request(step.method.clone(), &step.url, headers, step.body.clone())
                    .await
            }
            SequenceActor::Unauthenticated => {
                if step.method != Method::GET {
                    return Err(CapturedError::from_str(
                        "sequence/unauthenticated-method",
                        Some(step.url.clone()),
                        format!(
                            "Step '{}' uses unsupported unauthenticated method {}",
                            step.name, step.method
                        ),
                    ));
                }
                if step.body.is_some() || !step.headers.is_empty() {
                    return Err(CapturedError::from_str(
                        "sequence/unauthenticated-step-shape",
                        Some(step.url.clone()),
                        format!(
                            "Step '{}' includes body/headers not supported by unauthenticated flow",
                            step.name
                        ),
                    ));
                }
                self.primary.get_without_auth(&step.url).await
            }
        }
    }
}

fn build_header_map(headers: &[(String, String)]) -> Option<HeaderMap> {
    if headers.is_empty() {
        return None;
    }

    let mut map = HeaderMap::new();
    for (k, v) in headers {
        if let (Ok(name), Ok(value)) = (
            reqwest::header::HeaderName::from_bytes(k.as_bytes()),
            reqwest::header::HeaderValue::from_str(v),
        ) {
            map.insert(name, value);
        }
    }
    Some(map)
}
