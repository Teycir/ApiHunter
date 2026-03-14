// src/lib.rs
//
// Library entry point — re-exports modules so that integration tests
// and external consumers can reference them.

pub mod auth;
pub mod config;
pub mod cli;
#[allow(dead_code)]
pub mod discovery;
pub mod error;
pub mod http_client;
pub mod reports;
pub mod runner;
pub mod scanner;
pub mod waf;
