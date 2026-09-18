//! Human assistance requests are durable inbox items, never authorization decisions.
use crate::{Vault, VaultError};
use rusqlite::{params, OptionalExtension, Row};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssistanceScope {
    pub method: String,
    pub path: String,
    pub operation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssistanceRequest {
    pub id: String,
    pub client_id: String,
    pub harness: String,
    pub site: String,
    pub kind: String,
    pub requested_scope: Option<AssistanceScope>,
    pub reason: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

impl Vault {
    pub(crate) fn init_assistance_schema(&self) -> Result<(), VaultError> {
        self.conn.execute_batch("CREATE TABLE IF NOT EXISTS assistance_requests(id TEXT PRIMARY KEY,client_id TEXT NOT NULL,harness TEXT NOT NULL,site TEXT NOT NULL,kind TEXT NOT NULL,requested_scope TEXT NOT NULL,reason TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',created_at TEXT NOT NULL,updated_at TEXT NOT NULL); CREATE INDEX IF NOT EXISTS idx_assistance_owner_status ON assistance_requests(client_id,harness,status);")?;
        Ok(())
    }

    pub fn request_assistance(
        &mut self,
        client_id: &str,
        harness: &str,
        kind: &str,
        site: &str,
        mut scope: Option<AssistanceScope>,
        reason: &str,
    ) -> Result<AssistanceRequest, VaultError> {
        self.ensure_unlocked()?;
        let profile = self
            .get_harness(harness)?
            .ok_or(VaultError::InvalidAssistance)?;
        if profile.revoked_at.is_some() || crate::vault::is_expired(profile.expires_at.as_deref()) {
            return Err(VaultError::InvalidAssistance);
        }
        if client_id != "__legacy__"
            && !self.list_clients()?.iter().any(|c| {
                c.id == client_id
                    && c.harness == harness
                    && c.revoked_at.is_none()
                    && !crate::vault::is_expired(c.expires_at.as_deref())
            })
        {
            return Err(VaultError::InvalidAssistance);
        }
        let site =
            pman_protocol::decode_alias_ref(site).map_err(|_| VaultError::InvalidAssistance)?;
        let connection = self
            .list_sites()?
            .into_iter()
            .find(|s| s.alias == site)
            .ok_or(VaultError::InvalidAssistance)?;
        if connection.auth_type == "password" || !self.details(&site)?.ai_enabled {
            return Err(VaultError::InvalidAssistance);
        }
        match kind {
            "login" if scope.is_none() && crate::ipc::visible_to(self, harness, &site) => {}
            "access" => {
                let Some(requested) = scope.as_mut() else {
                    return Err(VaultError::InvalidAssistance);
                };
                requested.method = requested.method.to_ascii_uppercase();
                if !matches!(
                    requested.method.as_str(),
                    "GET" | "POST" | "PUT" | "PATCH" | "DELETE"
                ) || !matches!(requested.operation.as_str(), "query" | "write")
                    || requested.path.len() > 4096
                    || !requested.path.starts_with('/')
                    || pman_protocol::validate_policy_path(&requested.path).is_err()
                {
                    return Err(VaultError::InvalidAssistance);
                }
            }
            _ => return Err(VaultError::InvalidAssistance),
        }
        let secret = self.get_site_secret(&site).ok();
        let secrets = secret
            .as_ref()
            .map(|secret| crate::http_proxy::secret_values(secret, &connection))
            .unwrap_or_default();
        if scope
            .as_ref()
            .is_some_and(|s| secrets.iter().any(|secret| s.path.contains(secret)))
        {
            return Err(VaultError::InvalidAssistance);
        }
        let reason = redact_reason(reason, &secrets);
        let encoded_scope = serde_json::to_string(&scope)?;
        let duplicate:Option<AssistanceRequest>=self.conn.query_row("SELECT id,client_id,harness,site,kind,requested_scope,reason,status,created_at,updated_at FROM assistance_requests WHERE client_id=? AND harness=? AND site=? AND kind=? AND requested_scope=? AND status='pending' LIMIT 1",params![client_id,harness,site,kind,encoded_scope],from_row).optional()?;
        if let Some(request) = duplicate {
            return Ok(request);
        }
        let pending:i64=self.conn.query_row("SELECT COUNT(*) FROM assistance_requests WHERE client_id=? AND harness=? AND status='pending'",params![client_id,harness],|r|r.get(0))?;
        if pending >= 50 {
            return Err(VaultError::InvalidAssistance);
        }
        let now = crate::vault::now();
        let request = AssistanceRequest {
            id: uuid::Uuid::new_v4().simple().to_string(),
            client_id: client_id.into(),
            harness: harness.into(),
            site,
            kind: kind.into(),
            requested_scope: scope,
            reason,
            status: "pending".into(),
            created_at: now.clone(),
            updated_at: now,
        };
        self.conn.execute("INSERT INTO assistance_requests(id,client_id,harness,site,kind,requested_scope,reason,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",params![request.id,request.client_id,request.harness,request.site,request.kind,encoded_scope,request.reason,request.status,request.created_at,request.updated_at])?;
        self.add_audit(&crate::AuditEntryInput {
            harness: harness.into(),
            site: Some(request.site.clone()),
            req_id: Some(request.id.clone()),
            note: Some(format!("Human assistance requested: {kind}")),
            ..Default::default()
        })?;
        Ok(request)
    }

    pub fn list_assistance(
        &self,
        status: Option<&str>,
    ) -> Result<Vec<AssistanceRequest>, VaultError> {
        if status.is_some_and(|s| !matches!(s, "pending" | "handled" | "cancelled")) {
            return Err(VaultError::InvalidAssistance);
        }
        let mut stmt=self.conn.prepare("SELECT id,client_id,harness,site,kind,requested_scope,reason,status,created_at,updated_at FROM assistance_requests WHERE (?1 IS NULL OR status=?1) ORDER BY created_at DESC LIMIT 500")?;
        let rows = stmt.query_map([status], from_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn assistance_status(
        &self,
        id: &str,
        client_id: &str,
        harness: &str,
    ) -> Result<AssistanceRequest, VaultError> {
        self.conn.query_row("SELECT id,client_id,harness,site,kind,requested_scope,reason,status,created_at,updated_at FROM assistance_requests WHERE id=? AND client_id=? AND harness=?",params![id,client_id,harness],from_row).optional()?.ok_or(VaultError::InvalidAssistance)
    }

    /// Management must authenticate before calling this. Marking handled never creates a grant or session.
    pub fn decide_assistance(&mut self, id: &str, status: &str) -> Result<(), VaultError> {
        self.ensure_unlocked()?;
        if !matches!(status, "handled" | "cancelled") {
            return Err(VaultError::InvalidAssistance);
        }
        let changed = self.conn.execute(
            "UPDATE assistance_requests SET status=?,updated_at=? WHERE id=? AND status='pending'",
            params![status, crate::vault::now(), id],
        )?;
        if changed == 0 {
            return Err(VaultError::InvalidAssistance);
        }
        Ok(())
    }
}

fn from_row(row: &Row<'_>) -> rusqlite::Result<AssistanceRequest> {
    let scope: String = row.get(5)?;
    let requested_scope = serde_json::from_str(&scope).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
    })?;
    Ok(AssistanceRequest {
        id: row.get(0)?,
        client_id: row.get(1)?,
        harness: row.get(2)?,
        site: row.get(3)?,
        kind: row.get(4)?,
        requested_scope,
        reason: row.get(6)?,
        status: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}
fn redact_reason(reason: &str, secrets: &[String]) -> String {
    let mut reason = reason
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .take(1000)
        .collect::<String>();
    for secret in secrets {
        reason = reason.replace(secret, crate::REDACTED);
    }
    if let Ok(pattern) = regex::Regex::new(
        r"(?i)(bearer\s+|(?:password|passwd|token|cookie|eteamsid|session[_-]?id)\s*[:=]\s*)[^\s,;]+",
    ) {
        reason = pattern
            .replace_all(&reason, "$1***REDACTED***")
            .into_owned();
    }
    reason.chars().take(1000).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn assistance_is_scoped_redacted_durable_and_never_grants_access() {
        let temp = tempfile::tempdir().unwrap();
        let mut v = Vault::open(temp.path()).unwrap();
        v.create("synthetic-password").unwrap();
        v.add_site(crate::SiteInput::new(
            "api",
            "https://example.test",
            "api_token",
            json!({"token":"synthetic-secret"}),
        ))
        .unwrap();
        v.update_details("api", json!({"ai_enabled":true})).unwrap();
        v.pair_client("client", "client-1", &"a".repeat(64))
            .unwrap();
        assert!(v
            .request_assistance("client-1", "client", "login", "api", None, "")
            .is_err());
        let scope = AssistanceScope {
            method: "POST".into(),
            path: "/query".into(),
            operation: "query".into(),
        };
        let a = v
            .request_assistance(
                "client-1",
                "client",
                "access",
                "api",
                Some(scope.clone()),
                "token=synthetic-secret",
            )
            .unwrap();
        assert!(!a.reason.contains("synthetic-secret"));
        assert_eq!(v.get_policy("client").unwrap()["allow"], json!([]));
        let duplicate = v
            .request_assistance("client-1", "client", "access", "api", Some(scope), "again")
            .unwrap();
        assert_eq!(a.id, duplicate.id);
        assert!(v
            .assistance_status(&a.id, "other-client", "client")
            .is_err());
        v.decide_assistance(&a.id, "handled").unwrap();
        assert_eq!(v.get_policy("client").unwrap()["allow"], json!([]));
        v.add_allow_rule("client", "api", "GET", "/**").unwrap();
        let login = v
            .request_assistance("client-1", "client", "login", "api", None, "Please login")
            .unwrap();
        assert_eq!(login.status, "pending");
        drop(v);
        let v = Vault::open(temp.path()).unwrap();
        assert_eq!(
            v.assistance_status(&a.id, "client-1", "client")
                .unwrap()
                .status,
            "handled"
        );
    }
}
