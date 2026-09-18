//! Rust broker boundary. Storage and HTTP execution land here after protocol parity.

mod assistance;
mod backup;
mod broker;
pub mod browser;
mod check;
mod daemon;
pub mod e10;
mod http_proxy;
pub mod ipc;
pub mod oauth;
mod policy;
mod request_lifecycle;
pub mod status;
mod vault;
mod workspace;

pub use assistance::{AssistanceRequest, AssistanceScope};
pub use broker::{
    Authorization, Broker, BrokerError, BrokerResult, CompletedCall, PreparedCall, REDACTED,
};
pub use daemon::{DaemonClient, DaemonError};
pub use http_proxy::{CleanResponse, ProxyError, RawResponse};
pub use pman_protocol::{HttpRequest, ProtocolError, ResultEnvelope};
pub use policy::{
    AllowRule, ApprovalPolicy, Decision, DefaultAction, Policy, PolicyError, RateLimit,
    RateLimiter, RedactionPolicy, RequestConstraints,
};
pub use vault::{
    ApprovalSummary, AuditEntry, AuditEntryInput, HarnessSummary, SiteInput, SiteMetadataUpdate,
    SiteSummary, Vault, VaultError,
};
pub use workspace::{ClientSummary, ConnectionDetails, ScenarioMatch, ScenarioRoute};
pub use status::{CheckEvidence, ConnectionStatus, DimensionStatus};
pub use check::{execute_connection_check, CheckOutcome, ConnectionCheckPlan};
pub use browser::{WebSession, WebSessions};
pub use oauth::{
    normalize_origin as normalize_oauth_origin, OAuthError, OAuthStart, OAuthTokens,
};

/// Validate a request at the core boundary before any credential lookup.
pub fn validate_http_request(request: HttpRequest) -> Result<HttpRequest, ProtocolError> {
    request.validate()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_reuses_protocol_validation() {
        let request = HttpRequest {
            site: "gitlab".to_owned(),
            method: "GET".to_owned(),
            path: "/api/v4/version".to_owned(),
            capability: None,
            query: None,
            json_body: None,
            form: None,
        };
        assert!(validate_http_request(request).is_ok());
    }
}
