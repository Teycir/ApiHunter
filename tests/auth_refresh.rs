use std::sync::Arc;

use api_scanner::auth::{spawn_refresh_task, AuthFlow, InjectAs, LiveCredential};
use tokio::sync::RwLock;

#[tokio::test]
async fn refresh_task_can_be_cancelled_immediately() {
    let flow = AuthFlow {
        steps: vec![],
        refresh_interval_secs: 3600,
    };
    let cred = Arc::new(LiveCredential {
        value: Arc::new(RwLock::new("token".to_string())),
        refresh_value: None,
        inject_as: InjectAs::Bearer,
        refresh_lead_secs: 3600,
    });

    let handle = spawn_refresh_task(flow, cred);

    let res = tokio::time::timeout(std::time::Duration::from_secs(1), handle.shutdown()).await;
    assert!(res.is_ok(), "refresh task shutdown timed out");
}
