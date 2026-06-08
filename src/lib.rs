// src/lib.rs
//
// Library entry point — re-exports modules so that integration tests
// and external consumers can reference them.

pub mod auth;
pub mod auto_report;
pub mod browser_persona;
pub mod cli;
pub mod config;
#[allow(dead_code)]
pub mod discovery;
pub mod enrich;
pub mod error;
pub mod http_client;
pub mod progress_tracker;
pub mod proxy;
pub mod reports;
pub mod retry_policy;
pub mod runner;
pub mod scan_loader;
pub mod scanner;
pub mod threat_intel;
pub mod transport_adapter;
pub mod transport_tls;
pub mod waf;
