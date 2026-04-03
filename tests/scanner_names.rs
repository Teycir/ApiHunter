use std::sync::Arc;

use api_scanner::{
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    scanner::{
        api_security::ApiSecurityScanner, api_versioning::ApiVersioningScanner, cors::CorsScanner,
        csp::CspScanner, cve_templates::CveTemplateScanner, graphql::GraphqlScanner,
        grpc_protobuf::GrpcProtobufScanner, jwt::JwtScanner,
        mass_assignment::MassAssignmentScanner, oauth_oidc::OAuthOidcScanner,
        openapi::OpenApiScanner, rate_limit::RateLimitScanner, websocket::WebSocketScanner,
        Scanner,
    },
};

fn test_config() -> Config {
    Config {
        max_endpoints: 10,
        concurrency: 2,
        politeness: PolitenessConfig {
            delay_ms: 0,
            retries: 0,
            timeout_secs: 5,
        },
        waf_evasion: WafEvasionConfig {
            enabled: false,
            user_agents: vec![],
        },
        default_headers: vec![],
        cookies: vec![],
        proxy: None,
        danger_accept_invalid_certs: false,
        active_checks: true,
        dry_run: false,
        response_diff_deep: false,
        stream_findings: false,
        baseline_path: None,
        session_file: None,
        auth_bearer: None,
        auth_basic: None,
        auth_flow: None,
        auth_flow_b: None,
        unauth_strip_headers: vec![],
        per_host_clients: false,
        adaptive_concurrency: false,
        no_discovery: false,
        toggles: ScannerToggles {
            cors: true,
            csp: true,
            graphql: true,
            api_security: true,
            jwt: true,
            openapi: true,
            api_versioning: false,
            grpc_protobuf: false,
            mass_assignment: true,
            oauth_oidc: true,
            rate_limit: true,
            cve_templates: true,
            websocket: true,
        },
        quiet: false,
    }
}

#[test]
fn scanners_expose_stable_trait_names() {
    let cfg = test_config();
    let scanners: Vec<Arc<dyn Scanner>> = vec![
        Arc::new(CorsScanner::new(&cfg)),
        Arc::new(CspScanner::new(&cfg)),
        Arc::new(GraphqlScanner::new(&cfg)),
        Arc::new(ApiSecurityScanner::new(&cfg, None)),
        Arc::new(JwtScanner::new(&cfg)),
        Arc::new(OpenApiScanner::new(&cfg)),
        Arc::new(ApiVersioningScanner::new(&cfg)),
        Arc::new(GrpcProtobufScanner::new(&cfg)),
        Arc::new(MassAssignmentScanner::new(&cfg)),
        Arc::new(OAuthOidcScanner::new(&cfg)),
        Arc::new(RateLimitScanner::new(&cfg)),
        Arc::new(CveTemplateScanner::new(&cfg)),
        Arc::new(WebSocketScanner::new(&cfg)),
    ];

    let names: Vec<&str> = scanners.iter().map(|s| s.name()).collect();
    assert_eq!(
        names,
        vec![
            "cors",
            "csp",
            "graphql",
            "api_security",
            "jwt",
            "openapi",
            "api_versioning",
            "grpc_protobuf",
            "mass_assignment",
            "oauth_oidc",
            "rate_limit",
            "cve_templates",
            "websocket",
        ]
    );
}
