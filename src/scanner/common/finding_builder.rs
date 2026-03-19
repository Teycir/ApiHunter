use crate::reports::{Finding, Severity};

pub struct FindingBuilder {
    url: String,
    scanner: String,
    check: String,
    title: String,
    severity: Severity,
    detail: String,
}

impl FindingBuilder {
    pub fn new(url: &str, scanner: &str) -> Self {
        Self {
            url: url.to_string(),
            scanner: scanner.to_string(),
            check: String::new(),
            title: String::new(),
            severity: Severity::Info,
            detail: String::new(),
        }
    }

    pub fn check(mut self, check: impl Into<String>) -> Self {
        self.check = check.into();
        self
    }

    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    pub fn build(self) -> Finding {
        Finding::new(
            self.url,
            self.check,
            self.title,
            self.severity,
            self.detail,
            self.scanner,
        )
    }
}
