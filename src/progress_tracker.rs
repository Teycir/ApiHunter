//! Universal Progress Tracker
//!
//! A reusable progress tracking utility that automatically detects terminal capabilities
//! and provides appropriate output formatting for both TTY and non-TTY environments.
//!
//! ## Features
//! - Automatic TTY detection
//! - Thread-safe progress updates
//! - Configurable update frequency
//! - Clean output for both interactive and CI/CD environments
//!
//! ## Usage
//!
//! ```rust
//! use api_scanner::progress_tracker::ProgressTracker;
//!
//! #[tokio::main]
//! async fn main() {
//!     let tracker = ProgressTracker::new(100); // 100 total items
//!
//!     for _ in 0..100 {
//!         // Do work...
//!         tracker.increment(Some("Processing item")).await;
//!     }
//!
//!     tracker.finish().await;
//! }
//! ```

use std::io::{IsTerminal, Write};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

/// Configuration for progress tracking behavior
#[derive(Clone)]
pub struct ProgressConfig {
    /// Total number of items to process
    pub total: usize,
    /// Update frequency (every N items) for TTY mode
    pub tty_update_frequency: usize,
    /// Update frequency (every N items) for non-TTY mode
    pub non_tty_update_frequency: usize,
    /// Whether to show elapsed time
    pub show_elapsed: bool,
    /// Whether to show ETA
    pub show_eta: bool,
    /// Whether to show rate
    pub show_rate: bool,
    /// Custom prefix for progress messages
    pub prefix: String,
    /// Whether to show detailed messages (URLs, findings, etc.)
    pub show_details: bool,
}

impl Default for ProgressConfig {
    fn default() -> Self {
        Self {
            total: 0,
            tty_update_frequency: 5,
            non_tty_update_frequency: 1,
            show_elapsed: true,
            show_eta: true,
            show_rate: true,
            prefix: String::new(),
            show_details: true,
        }
    }
}

/// Thread-safe progress tracker
pub struct ProgressTracker {
    config: ProgressConfig,
    progress: Arc<Mutex<usize>>,
    start_time: Instant,
    is_tty: bool,
}

impl ProgressTracker {
    /// Create a new progress tracker with default configuration
    pub fn new(total: usize) -> Self {
        Self::with_config(ProgressConfig {
            total,
            ..Default::default()
        })
    }

    /// Create a new progress tracker with custom configuration
    pub fn with_config(config: ProgressConfig) -> Self {
        Self {
            config,
            progress: Arc::new(Mutex::new(0)),
            start_time: Instant::now(),
            is_tty: std::io::stderr().is_terminal(),
        }
    }

    /// Get a cloneable handle for use in async tasks
    pub fn handle(&self) -> ProgressHandle {
        ProgressHandle {
            config: self.config.clone(),
            progress: Arc::clone(&self.progress),
            start_time: self.start_time,
            is_tty: self.is_tty,
        }
    }

    /// Increment progress by 1 and optionally display a message
    pub async fn increment(&self, message: Option<&str>) {
        let mut p = self.progress.lock().await;
        *p += 1;
        let current = *p;
        drop(p);

        self.display_progress(current, message).await;
    }

    /// Set progress to a specific value
    pub async fn set(&self, value: usize, message: Option<&str>) {
        let mut p = self.progress.lock().await;
        *p = value;
        drop(p);

        self.display_progress(value, message).await;
    }

    /// Get current progress value
    pub async fn current(&self) -> usize {
        *self.progress.lock().await
    }

    /// Display progress based on TTY detection
    async fn display_progress(&self, current: usize, message: Option<&str>) {
        let update_freq = if self.is_tty {
            self.config.tty_update_frequency
        } else {
            self.config.non_tty_update_frequency
        };

        // Only display at specified frequency or when complete
        if !current.is_multiple_of(update_freq) && current != self.config.total {
            return;
        }

        let elapsed = self.start_time.elapsed().as_secs();
        let percentage = if self.config.total > 0 {
            (current as f64 / self.config.total as f64) * 100.0
        } else {
            0.0
        };

        if self.is_tty {
            // TTY mode: use carriage return for same-line updates
            let mut output = format!(
                "\r{}{}/{} ({:.1}%)",
                self.config.prefix, current, self.config.total, percentage
            );

            if self.config.show_rate && elapsed > 0 {
                let rate = current as f64 / elapsed as f64;
                output.push_str(&format!(" | {:.1}/s", rate));
            }

            if self.config.show_eta && elapsed > 0 && current > 0 {
                let rate = current as f64 / elapsed as f64;
                let remaining = self.config.total.saturating_sub(current);
                let eta_secs = (remaining as f64 / rate) as u64;
                let eta_mins = eta_secs / 60;
                output.push_str(&format!(" | ETA: {}m{}s", eta_mins, eta_secs % 60));
            }

            if self.config.show_elapsed {
                output.push_str(&format!(" | Elapsed: {}s", elapsed));
            }

            if self.config.show_details {
                if let Some(msg) = message {
                    output.push_str(&format!(" | {}", msg));
                }
            }

            output.push_str("   "); // Clear any leftover characters

            eprint!("{}", output);
            std::io::stderr().flush().ok();
        } else {
            // Non-TTY mode: new line for each update
            let mut output = format!("[{}/{}] ({:.1}%)", current, self.config.total, percentage);

            if !self.config.prefix.is_empty() {
                output = format!("{} {}", self.config.prefix, output);
            }

            if self.config.show_elapsed {
                output.push_str(&format!(" | Elapsed: {}s", elapsed));
            }

            if self.config.show_details {
                if let Some(msg) = message {
                    output.push_str(&format!(" | {}", msg));
                }
            }

            eprintln!("{}", output);
        }
    }

    /// Finish progress tracking and clear the line (TTY mode)
    pub async fn finish(&self) {
        if self.is_tty {
            eprintln!(); // Move to next line
        }
        let elapsed = self.start_time.elapsed();
        eprintln!(
            "✅ Completed {} items in {:.2}s",
            self.config.total,
            elapsed.as_secs_f64()
        );
    }
}

/// Cloneable handle for use in async tasks
#[derive(Clone)]
pub struct ProgressHandle {
    config: ProgressConfig,
    progress: Arc<Mutex<usize>>,
    start_time: Instant,
    is_tty: bool,
}

impl ProgressHandle {
    /// Increment progress by 1
    pub async fn increment(&self, message: Option<&str>) {
        let mut p = self.progress.lock().await;
        *p += 1;
        let current = *p;
        drop(p);

        self.display_progress(current, message).await;
    }

    /// Get current progress value
    pub async fn current(&self) -> usize {
        *self.progress.lock().await
    }

    async fn display_progress(&self, current: usize, message: Option<&str>) {
        let update_freq = if self.is_tty {
            self.config.tty_update_frequency
        } else {
            self.config.non_tty_update_frequency
        };

        if !current.is_multiple_of(update_freq) && current != self.config.total {
            return;
        }

        let elapsed = self.start_time.elapsed().as_secs();
        let percentage = if self.config.total > 0 {
            (current as f64 / self.config.total as f64) * 100.0
        } else {
            0.0
        };

        if self.is_tty {
            let mut output = format!(
                "\r{}{}/{} ({:.1}%)",
                self.config.prefix, current, self.config.total, percentage
            );

            if self.config.show_rate && elapsed > 0 {
                let rate = current as f64 / elapsed as f64;
                output.push_str(&format!(" | {:.1}/s", rate));
            }

            if self.config.show_eta && elapsed > 0 && current > 0 {
                let rate = current as f64 / elapsed as f64;
                let remaining = self.config.total.saturating_sub(current);
                let eta_secs = (remaining as f64 / rate) as u64;
                let eta_mins = eta_secs / 60;
                output.push_str(&format!(" | ETA: {}m{}s", eta_mins, eta_secs % 60));
            }

            if self.config.show_elapsed {
                output.push_str(&format!(" | Elapsed: {}s", elapsed));
            }

            if self.config.show_details {
                if let Some(msg) = message {
                    output.push_str(&format!(" | {}", msg));
                }
            }

            output.push_str("   ");

            eprint!("{}", output);
            std::io::stderr().flush().ok();
        } else {
            let mut output = format!("[{}/{}] ({:.1}%)", current, self.config.total, percentage);

            if !self.config.prefix.is_empty() {
                output = format!("{} {}", self.config.prefix, output);
            }

            if self.config.show_elapsed {
                output.push_str(&format!(" | Elapsed: {}s", elapsed));
            }

            if self.config.show_details {
                if let Some(msg) = message {
                    output.push_str(&format!(" | {}", msg));
                }
            }

            eprintln!("{}", output);
        }
    }
}
