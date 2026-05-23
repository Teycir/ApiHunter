// src/triage/sources/mod.rs
//
// Source probe modules used by the triage engine.
// Each module exposes an async `fetch` function that returns a
// `SourceOutcome<T>` — never panics, never silently swallows errors.

pub mod internetdb;
pub mod ipinfo;
pub mod rdap;
