//! Native workspace metadata and identities. None of these public summaries contain secrets.
use crate::vault::now;
use crate::{Vault, VaultError};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ScenarioRoute {
    /// Stable business intent such as `jenkins.build`.
    pub intent: String,
    /// Capability that the eventual HTTP request must present.
    pub capability: String,
    /// Optional service allow-list. Glob syntax matches policy paths.
    pub services: Vec<String>,
    /// Additional selectors such as branch or baseline.
    pub selectors: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScenarioMatch {
    pub site: String,
    pub intent: String,
    pub capability: String,
    pub environment: String,
    pub account: String,
    pub services: Vec<String>,
    pub selectors: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnectionDetails {
    pub group: String,
    pub favorite: bool,
    pub account: String,
    pub environment: String,
    pub tenant: String,
    pub notes: String,
    pub ai_enabled: bool,
    pub scenarios: Vec<ScenarioRoute>,
    /// Optional provider hint for the read-only connection check:
    /// `github`, `gitlab` or `custom`. Absent means auto-detect by host.
    pub provider: Option<String>,
    /// Read-only check path for custom providers, e.g. `/api/v1/me`.
    /// Empty/absent means an unknown service without a check path.
    pub check_path: Option<String>,
    /// User-registered OAuth application client id (public client, no
    /// secret). Absent means OAuth is unconfigured and the Token path stays.
    pub oauth_client_id: Option<String>,
    /// OAuth scope request. Defaults to the provider's minimum read scope.
    pub oauth_scope: Option<String>,
    /// Microsoft tenant slot (`organizations` / `consumers` / `common` or a
    /// tenant id). Only read by the Microsoft provider; absent keeps the
    /// `organizations` default. Serde default keeps old vaults compatible.
    pub oauth_tenant: Option<String>,
    /// Independent browser capability (BROWSER-CONTRACT.md). Default false:
    /// existing API authorization never grants web access.
    pub web_enabled: bool,
    pub extra: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSummary {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub harness: String,
    pub paired: bool,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
}

impl Vault {
    /// Human-confirmed connection-wide consent. Validate every recipient before
    /// writing, then enable the connection and append policies atomically.
    pub fn grant_connection_clients(
        &mut self,
        alias: &str,
        client_ids: &[String],
    ) -> Result<(), VaultError> {
        self.ensure_unlocked()?;
        let site = self
            .list_sites()?
            .into_iter()
            .find(|s| s.alias == alias)
            .ok_or_else(|| VaultError::UnknownSite(alias.into()))?;
        if site.auth_type == "password" || site.site_url.is_empty() || client_ids.is_empty() {
            return Err(VaultError::InvalidSchema(
                "请选择连接和至少一个有效的 AI 客户端".into(),
            ));
        }
        let clients = self.list_clients()?;
        let rule = serde_json::json!({"site":alias,"methods":["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"],"paths":["/**"],"require_approval":false});
        let mut policies = BTreeMap::new();
        for id in client_ids {
            let client = clients
                .iter()
                .find(|c| {
                    &c.id == id
                        && c.paired
                        && c.revoked_at.is_none()
                        && !expired(c.expires_at.as_deref())
                })
                .ok_or(VaultError::InvalidClient)?;
            let harness = self
                .get_harness(&client.harness)?
                .ok_or(VaultError::InvalidClient)?;
            if harness.revoked_at.is_some() || expired(harness.expires_at.as_deref()) {
                return Err(VaultError::InvalidClient);
            }
            let mut policy = self.get_policy(&client.harness)?;
            let object = policy
                .as_object_mut()
                .ok_or_else(|| VaultError::InvalidSchema("invalid policy".into()))?;
            let allow = object
                .entry("allow")
                .or_insert_with(|| serde_json::json!([]))
                .as_array_mut()
                .ok_or_else(|| VaultError::InvalidSchema("invalid allow rules".into()))?;
            if !allow.contains(&rule) {
                allow.push(rule.clone());
            }
            crate::Policy::from_json(&policy)
                .map_err(|e| VaultError::InvalidSchema(e.to_string()))?;
            policies.insert(client.harness.clone(), serde_json::to_string(&policy)?);
        }
        let mut details = self.details(alias)?;
        details.ai_enabled = true;
        let details_json = serde_json::to_string(&details)?;
        let tx = self.conn.transaction()?;
        for (harness, policy) in policies {
            tx.execute(
                "UPDATE harnesses SET policy_json=? WHERE name=?",
                params![policy, harness],
            )?;
        }
        tx.execute("INSERT INTO connection_details(alias,details_json) VALUES(?,?) ON CONFLICT(alias) DO UPDATE SET details_json=excluded.details_json", params![alias, details_json])?;
        tx.commit()?;
        self.invalidate_requests();
        Ok(())
    }

    pub(crate) fn init_workspace_schema(&self) -> Result<(), VaultError> {
        self.conn.execute_batch("CREATE TABLE IF NOT EXISTS connection_details (alias TEXT PRIMARY KEY, details_json TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS native_clients (id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, harness TEXT NOT NULL, proof_hash TEXT NOT NULL, created_at TEXT NOT NULL, last_used_at TEXT, expires_at TEXT, revoked_at TEXT);")?;
        Ok(())
    }

    /// Missing details belong to migrated legacy connections whose policies remain effective.
    pub fn details(&self, alias: &str) -> Result<ConnectionDetails, VaultError> {
        let raw: Option<String> = self
            .conn
            .query_row(
                "SELECT details_json FROM connection_details WHERE alias=?",
                [alias],
                |r| r.get(0),
            )
            .optional()?;
        match raw {
            Some(raw) => Ok(serde_json::from_str(&raw)?),
            None => Ok(ConnectionDetails {
                ai_enabled: true,
                ..Default::default()
            }),
        }
    }

    pub fn update_details(
        &mut self,
        alias: &str,
        patch: Value,
    ) -> Result<ConnectionDetails, VaultError> {
        self.ensure_unlocked()?;
        if !self.list_sites()?.iter().any(|s| s.alias == alias) {
            return Err(VaultError::UnknownSite(alias.into()));
        }
        let patch = patch.as_object().ok_or(VaultError::InvalidSecret)?;
        let previous = self.details(alias)?;
        let mut value = serde_json::to_value(&previous)?;
        let object = value.as_object_mut().ok_or(VaultError::InvalidSecret)?;
        for (key, value) in patch {
            object.insert(key.clone(), value.clone());
        }
        let mut details: ConnectionDetails = serde_json::from_value(value)?;
        validate_scenarios(&details.scenarios)?;
        if previous.account != details.account
            || previous.tenant != details.tenant
            || ["user_id", "tenant_key"].iter().any(|k| {
                previous.extra.get(k).is_some() && previous.extra.get(k) != details.extra.get(k)
            })
        {
            self.revoke_connection_grants(alias)?;
            details.ai_enabled = false;
        }
        self.conn.execute("INSERT INTO connection_details(alias,details_json) VALUES(?,?) ON CONFLICT(alias) DO UPDATE SET details_json=excluded.details_json", params![alias,serde_json::to_string(&details)?])?;
        self.invalidate_requests();
        Ok(details)
    }

    /// Resolve a business intent to visible, AI-enabled connections. Returning
    /// every match lets the caller fail closed when context is ambiguous.
    pub fn resolve_scenario(
        &self,
        harness: &str,
        intent: &str,
        context: &BTreeMap<String, String>,
    ) -> Result<Vec<ScenarioMatch>, VaultError> {
        let intent = intent.trim();
        if !valid_identifier(intent) || context.len() > 32 {
            return Err(VaultError::InvalidSchema("invalid scenario query".into()));
        }
        let policy = crate::Policy::from_json(&self.get_policy(harness)?)
            .map_err(|error| VaultError::InvalidSchema(error.to_string()))?;
        let requested_environment = context.get("environment").map(|value| value.trim());
        let requested_service = context.get("service").map(|value| value.trim());
        let mut matches = Vec::new();
        for site in self.list_sites()? {
            if site.auth_type == "password"
                || site.status != "active"
                || crate::vault::is_expired(site.expires_at.as_deref())
                || !(policy.default_action == crate::DefaultAction::Allow
                    || policy.allow.iter().any(|rule| {
                        rule.site == site.alias
                            && !crate::vault::is_expired(rule.expires_at.as_deref())
                    }))
            {
                continue;
            }
            let details = self.details(&site.alias)?;
            if !details.ai_enabled
                || requested_environment
                    .is_some_and(|value| !value.eq_ignore_ascii_case(details.environment.trim()))
            {
                continue;
            }
            for route in &details.scenarios {
                if !route.intent.eq_ignore_ascii_case(intent) {
                    continue;
                }
                if !route.services.is_empty()
                    && !requested_service.is_some_and(|service| {
                        route
                            .services
                            .iter()
                            .any(|pattern| crate::policy::glob_match(pattern, service))
                    })
                {
                    continue;
                }
                let selectors_match = route.selectors.iter().all(|(key, patterns)| {
                    context.get(key).is_some_and(|actual| {
                        patterns
                            .iter()
                            .any(|pattern| crate::policy::glob_match(pattern, actual))
                    })
                });
                if selectors_match {
                    let candidate = ScenarioMatch {
                        site: site.alias.clone(),
                        intent: route.intent.clone(),
                        capability: route.capability.clone(),
                        environment: details.environment.clone(),
                        account: details.account.clone(),
                        services: route.services.clone(),
                        selectors: route.selectors.clone(),
                    };
                    if !matches.contains(&candidate) {
                        matches.push(candidate);
                    }
                }
            }
        }
        Ok(matches)
    }

    pub fn pair_client(
        &mut self,
        name: &str,
        id: &str,
        verifier: &str,
    ) -> Result<ClientSummary, VaultError> {
        self.pair_client_for(name, "generic", name, id, verifier)
    }

    pub fn pair_client_for(
        &mut self,
        name: &str,
        kind: &str,
        harness: &str,
        id: &str,
        verifier: &str,
    ) -> Result<ClientSummary, VaultError> {
        self.ensure_unlocked()?;
        if !valid_client_id(id)
            || verifier.len() != 64
            || !verifier.bytes().all(|c| c.is_ascii_hexdigit())
            || name.trim().is_empty()
            || harness.trim().is_empty()
        {
            return Err(VaultError::InvalidClient);
        }
        self.ensure_harness(harness)?;
        self.conn.execute("INSERT INTO native_clients(id,name,kind,harness,proof_hash,created_at) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,kind=excluded.kind,harness=excluded.harness,proof_hash=excluded.proof_hash,revoked_at=NULL,expires_at=NULL", params![id,name,kind,harness,verifier,now()])?;
        self.invalidate_requests();
        self.list_clients()?
            .into_iter()
            .find(|c| c.id == id)
            .ok_or(VaultError::InvalidClient)
    }

    pub fn list_clients(&self) -> Result<Vec<ClientSummary>, VaultError> {
        let mut stmt = self.conn.prepare("SELECT id,name,kind,harness,created_at,last_used_at,expires_at,revoked_at FROM native_clients ORDER BY created_at DESC")?;
        let rows = stmt.query_map([], |r| {
            let revoked_at: Option<String> = r.get(7)?;
            Ok(ClientSummary {
                id: r.get(0)?,
                name: r.get(1)?,
                kind: r.get(2)?,
                harness: r.get(3)?,
                paired: revoked_at.is_none(),
                created_at: r.get(4)?,
                last_used_at: r.get(5)?,
                expires_at: r.get(6)?,
                revoked_at,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn revoke_client(&mut self, id: &str) -> Result<(), VaultError> {
        self.ensure_unlocked()?;
        self.conn.execute(
            "UPDATE native_clients SET revoked_at=?,proof_hash='' WHERE id=?",
            params![now(), id],
        )?;
        self.conn.execute("UPDATE assistance_requests SET status='cancelled',updated_at=? WHERE client_id=? AND status='pending'",params![now(),id])?;
        self.invalidate_requests();
        Ok(())
    }

    pub fn authenticate_client(&mut self, id: &str, proof: &str) -> Result<String, VaultError> {
        if !valid_client_id(id) || proof.len() != 64 {
            return Err(VaultError::InvalidClient);
        }
        let row: Option<(String, String, Option<String>, Option<String>)> = self
            .conn
            .query_row(
                "SELECT harness,proof_hash,expires_at,revoked_at FROM native_clients WHERE id=?",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let Some((harness, expected, expiry, revoked)) = row else {
            return Err(VaultError::InvalidClient);
        };
        let digest = hex::encode(Sha256::digest(proof.as_bytes()));
        if !constant_eq(digest.as_bytes(), expected.as_bytes())
            || revoked.is_some()
            || expired(expiry.as_deref())
        {
            return Err(VaultError::InvalidClient);
        }
        let profile = self
            .get_harness(&harness)?
            .ok_or(VaultError::InvalidClient)?;
        if profile.revoked_at.is_some() || expired(profile.expires_at.as_deref()) {
            return Err(VaultError::InvalidClient);
        }
        self.conn.execute(
            "UPDATE native_clients SET last_used_at=? WHERE id=?",
            params![now(), id],
        )?;
        Ok(harness)
    }

    /// Hash-only compatibility for existing harness tokens and short-lived leases.
    pub fn authenticate_legacy_token(&mut self, token: &str) -> Result<String, VaultError> {
        if token.is_empty() {
            return Err(VaultError::InvalidClient);
        }
        let digest = hex::encode(Sha256::digest(token.as_bytes()));
        let direct:Option<String>=self.conn.query_row("SELECT name FROM harnesses WHERE token_hash=? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>?)",params![digest,now()],|r|r.get(0)).optional()?;
        if let Some(name) = direct {
            return Ok(name);
        }
        let lease:Option<(String,String)>=self.conn.query_row("SELECT l.id,l.harness FROM leases l JOIN harnesses h ON h.name=l.harness WHERE l.token_hash=? AND l.revoked_at IS NULL AND l.expires_at>? AND h.revoked_at IS NULL AND (h.expires_at IS NULL OR h.expires_at>?)",params![digest,now(),now()],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let Some((id, harness)) = lease else {
            return Err(VaultError::InvalidClient);
        };
        self.conn.execute(
            "UPDATE leases SET last_used_at=? WHERE id=?",
            params![now(), id],
        )?;
        Ok(harness)
    }

    /// SQLite online backup includes the WAL consistently and excludes DPAPI files.
    pub fn backup_to(&self, destination: &Path) -> Result<(), VaultError> {
        self.ensure_unlocked()?;
        if destination.exists() {
            return Err(VaultError::InvalidSchema(
                "backup target already exists".into(),
            ));
        }
        self.conn
            .backup(rusqlite::DatabaseName::Main, destination, None)?;
        Ok(())
    }

    pub fn forget_native_pairings(&mut self) -> Result<(), VaultError> {
        self.conn.execute("DELETE FROM native_clients", [])?;
        self.conn.execute(
            "UPDATE assistance_requests SET status='cancelled',updated_at=? WHERE status='pending'",
            [now()],
        )?;
        self.invalidate_requests();
        Ok(())
    }

    /// Rebinding an alias to another account or origin must not inherit previous consent.
    pub(crate) fn revoke_connection_grants(&mut self, alias: &str) -> Result<(), VaultError> {
        self.conn.execute("UPDATE assistance_requests SET status='cancelled',updated_at=? WHERE site=? AND status='pending'",params![now(),alias])?;
        for profile in self.list_harnesses()? {
            let mut policy = profile.policy;
            if let Some(allow) = policy.get_mut("allow").and_then(Value::as_array_mut) {
                let before = allow.len();
                allow.retain(|r| r.get("site").and_then(Value::as_str) != Some(alias));
                if before != allow.len() {
                    self.set_policy(&profile.name, policy)?;
                }
            }
        }
        self.conn.execute("UPDATE approvals SET status='denied',decided_at=?,decided_by='connection_changed' WHERE site=? AND status IN ('pending','approved') AND consumed_at IS NULL",params![now(),alias])?;
        self.invalidate_requests();
        Ok(())
    }

    /// Import a read-only database copy. The original database and its WAL are never changed.
    pub fn import_snapshot(
        source: &Path,
        destination_home: &Path,
        password: &str,
        restore_backup: bool,
    ) -> Result<Self, VaultError> {
        if destination_home.join("vault.db").exists() {
            return Err(VaultError::AlreadyInitialized);
        }
        std::fs::create_dir_all(destination_home)?;
        let stage = destination_home.join(format!("import-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&stage)?;
        let result = (|| {
            let original = rusqlite::Connection::open_with_flags(
                source,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;
            original.backup(rusqlite::DatabaseName::Main, stage.join("vault.db"), None)?;
            let mut imported = Vault::open(&stage)?;
            imported.unlock(password)?;
            for site in imported
                .list_sites()?
                .into_iter()
                .filter(|s| s.status == "active")
            {
                let _ = imported.get_site_secret(&site.alias)?;
            }
            if restore_backup {
                imported.forget_native_pairings()?;
                imported
                    .conn
                    .execute("UPDATE harnesses SET token_hash=NULL", [])?;
                imported
                    .conn
                    .execute("UPDATE leases SET revoked_at=?", [now()])?;
            }
            imported
                .conn
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
            drop(imported);
            drop(original);
            std::fs::rename(stage.join("vault.db"), destination_home.join("vault.db"))?;
            let mut vault = Vault::open(destination_home)?;
            vault.unlock(password)?;
            Ok(vault)
        })();
        // The staging directory is generated under destination_home and contains only this import's files.
        let _ = std::fs::remove_dir_all(stage);
        result
    }
}

pub fn valid_client_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 100
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
}
fn validate_scenarios(routes: &[ScenarioRoute]) -> Result<(), VaultError> {
    if routes.len() > 100 {
        return Err(VaultError::InvalidSchema("too many scenario routes".into()));
    }
    for route in routes {
        if !valid_identifier(route.intent.trim())
            || !valid_identifier(route.capability.trim())
            || route
                .services
                .iter()
                .any(|value| value.is_empty() || value.len() > 256)
            || route.selectors.iter().any(|(key, values)| {
                !valid_identifier(key)
                    || values.is_empty()
                    || values
                        .iter()
                        .any(|value| value.is_empty() || value.len() > 256)
            })
        {
            return Err(VaultError::InvalidSchema("invalid scenario route".into()));
        }
    }
    Ok(())
}
fn expired(expiry: Option<&str>) -> bool {
    crate::vault::is_expired(expiry)
}
fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |v, (a, b)| v | (a ^ b)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn connection_fixture() -> (tempfile::TempDir, Vault) {
        let temp = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(temp.path()).unwrap();
        vault.create("synthetic-password").unwrap();
        vault
            .add_site(crate::SiteInput::new(
                "api",
                "https://example.test",
                "api_token",
                json!({"token":"synthetic-only"}),
            ))
            .unwrap();
        for id in ["client-one", "client-two"] {
            vault
                .pair_client_for(id, "generic", id, id, &"a".repeat(64))
                .unwrap();
        }
        (temp, vault)
    }
    #[test]
    fn connection_grant_is_scoped_idempotent_and_preserves_denies() {
        let (_temp, mut vault) = connection_fixture();
        vault.set_policy("client-one", json!({"allow":[{"site":"other","methods":["GET"],"paths":["/read"]}],"deny":[{"site":"api","methods":["DELETE"],"paths":["/protected"]}],"approval":{"required_for":["POST"]}})).unwrap();
        let ids = vec!["client-one".into(), "client-two".into()];
        vault.grant_connection_clients("api", &ids).unwrap();
        let first = vault.get_policy("client-one").unwrap();
        vault.grant_connection_clients("api", &ids).unwrap();
        assert_eq!(vault.get_policy("client-one").unwrap(), first);
        assert!(vault.details("api").unwrap().ai_enabled);
        let policy = crate::Policy::from_json(&first).unwrap();
        assert!(policy.authorize("api", "POST", "/new/path").allowed);
        assert!(!policy.approval_required_for("api", "POST", "/new/path"));
        assert!(!policy.authorize("api", "DELETE", "/protected").allowed);
        assert!(!policy.authorize("unselected", "POST", "/new/path").allowed);
        assert!(policy.authorize("other", "GET", "/read").allowed);
        let rule = first["allow"].as_array().unwrap().last().unwrap().clone();
        vault.remove_allow_rule("client-one", rule).unwrap();
        assert!(
            !crate::Policy::from_json(&vault.get_policy("client-one").unwrap())
                .unwrap()
                .authorize("api", "GET", "/new/path")
                .allowed
        );
    }
    #[test]
    fn connection_grant_rejects_invalid_recipient_without_partial_writes() {
        let (_temp, mut vault) = connection_fixture();
        let before = vault.get_policy("client-one").unwrap();
        assert!(vault
            .grant_connection_clients("api", &["client-one".into(), "missing".into()])
            .is_err());
        assert_eq!(before, vault.get_policy("client-one").unwrap());
        assert!(!vault.details("api").unwrap().ai_enabled);
        vault.revoke_client("client-two").unwrap();
        assert!(vault
            .grant_connection_clients("api", &["client-one".into(), "client-two".into()])
            .is_err());
        assert_eq!(before, vault.get_policy("client-one").unwrap());
        assert!(vault.grant_connection_clients("api", &[]).is_err());
    }
    #[test]
    fn connection_grant_rejects_passwords_and_locked_vaults() {
        let (_temp, mut vault) = connection_fixture();
        vault
            .add_site(crate::SiteInput::new(
                "personal",
                "",
                "password",
                json!({"password":"synthetic-only"}),
            ))
            .unwrap();
        assert!(vault
            .grant_connection_clients("personal", &["client-one".into()])
            .is_err());
        vault.lock();
        assert!(vault
            .grant_connection_clients("api", &["client-one".into()])
            .is_err());
    }
    #[test]
    fn identity_is_proof_bound_revocable_and_not_name_bound() {
        let t = tempfile::tempdir().unwrap();
        let mut v = Vault::open(t.path()).unwrap();
        v.create("synthetic-password").unwrap();
        let proof = "a".repeat(64);
        let digest = hex::encode(Sha256::digest(proof.as_bytes()));
        v.pair_client_for("Codex", "codex", "codex", "client-1", &digest)
            .unwrap();
        assert!(v.authenticate_client("client-1", &"b".repeat(64)).is_err());
        assert_eq!(v.authenticate_client("client-1", &proof).unwrap(), "codex");
        v.revoke_client("client-1").unwrap();
        assert!(v.authenticate_client("client-1", &proof).is_err());
    }
    #[test]
    fn resume_does_not_need_password_and_management_verification_does_not_pause() {
        let t = tempfile::tempdir().unwrap();
        let mut v = Vault::open(t.path()).unwrap();
        v.create("synthetic-password").unwrap();
        let key = v.export_resume_key().unwrap();
        assert!(v.verify_password("wrong").is_err());
        assert!(v.unlocked());
        v.lock();
        let generation = v.generation();
        v.resume_with_key(&key).unwrap();
        assert!(v.unlocked());
        assert_eq!(v.generation(), generation);
        assert!(v.resume_with_key(&[1u8; 32]).is_err());
    }
    #[test]
    fn metadata_never_includes_secret() {
        let t = tempfile::tempdir().unwrap();
        let mut v = Vault::open(t.path()).unwrap();
        v.create("synthetic-password").unwrap();
        v.add_site(crate::SiteInput::new(
            "Personal",
            "",
            "password",
            json!({"password":"synthetic-secret"}),
        ))
        .unwrap();
        assert!(!v.details("Personal").unwrap().ai_enabled);
        assert!(!serde_json::to_string(&v.list_sites().unwrap())
            .unwrap()
            .contains("synthetic-secret"));
    }
    #[test]
    fn legacy_token_and_lease_identity_preserves_revocation_and_expiry() {
        let temp = tempfile::tempdir().unwrap();
        let mut v = Vault::open(temp.path()).unwrap();
        v.create("synthetic-password").unwrap();
        v.ensure_harness("legacy").unwrap();
        let token = "synthetic-token";
        let hash = hex::encode(Sha256::digest(token.as_bytes()));
        v.conn
            .execute(
                "UPDATE harnesses SET token_hash=? WHERE name='legacy'",
                [&hash],
            )
            .unwrap();
        assert_eq!(v.authenticate_legacy_token(token).unwrap(), "legacy");
        v.conn
            .execute(
                "UPDATE harnesses SET expires_at='2001-01-01T00:00:00' WHERE name='legacy'",
                [],
            )
            .unwrap();
        assert!(v.authenticate_legacy_token(token).is_err());
        v.conn
            .execute(
                "UPDATE harnesses SET token_hash=NULL,expires_at=NULL WHERE name='legacy'",
                [],
            )
            .unwrap();
        v.conn.execute("INSERT INTO leases(id,harness,token_hash,created_at,expires_at) VALUES('lease','legacy',?,?, '2099-01-01T00:00:00')",params![hash,now()]).unwrap();
        assert_eq!(v.authenticate_legacy_token(token).unwrap(), "legacy");
        v.conn
            .execute("UPDATE leases SET revoked_at=? WHERE id='lease'", [now()])
            .unwrap();
        assert!(v.authenticate_legacy_token(token).is_err());
    }

    #[test]
    fn rebinding_account_revokes_scopes_and_disables_ai_access() {
        let temp = tempfile::tempdir().unwrap();
        let mut v = Vault::open(temp.path()).unwrap();
        v.create("synthetic-password").unwrap();
        v.add_site(crate::SiteInput::new(
            "api",
            "https://example.test",
            "api_token",
            serde_json::json!({"token":"synthetic-token"}),
        ))
        .unwrap();
        v.update_details("api", serde_json::json!({"account":"first"}))
            .unwrap();
        v.update_details("api", serde_json::json!({"ai_enabled":true}))
            .unwrap();
        v.ensure_harness("client").unwrap();
        v.add_allow_rule("client", "api", "GET", "/**").unwrap();
        let result = v
            .update_details(
                "api",
                serde_json::json!({"account":"second","ai_enabled":true}),
            )
            .unwrap();
        assert!(!result.ai_enabled);
        assert_eq!(
            v.get_policy("client").unwrap()["allow"],
            serde_json::json!([])
        );
    }

    #[test]
    fn scenario_resolution_requires_a_unique_environment_and_keeps_account_bound() {
        let temp = tempfile::tempdir().unwrap();
        let mut v = Vault::open(temp.path()).unwrap();
        v.create("synthetic-password").unwrap();
        for (alias, environment, account) in [
            ("jenkins-test", "test", "builder"),
            ("jenkins-release", "baseline", "releaser"),
        ] {
            v.add_site(crate::SiteInput::new(
                alias,
                "https://jenkins.example.test",
                "api_token",
                serde_json::json!({"token":"synthetic-token"}),
            ))
            .unwrap();
            v.update_details(
                alias,
                serde_json::json!({
                    "environment":environment,
                    "account":account,
                    "scenarios":[{
                        "intent":"jenkins.build",
                        "capability":format!("jenkins.build.{environment}"),
                        "services":["web-*"],
                        "selectors":{}
                    }]
                }),
            )
            .unwrap();
            v.update_details(alias, serde_json::json!({"ai_enabled":true}))
                .unwrap();
        }
        v.ensure_harness("client").unwrap();
        v.set_policy(
            "client",
            serde_json::json!({"allow":[
                {"site":"jenkins-test","methods":["POST"],"paths":["/build"]},
                {"site":"jenkins-release","methods":["POST"],"paths":["/build"]}
            ]}),
        )
        .unwrap();
        let context = BTreeMap::from([("service".to_owned(), "web-api".to_owned())]);
        assert_eq!(
            v.resolve_scenario("client", "jenkins.build", &context)
                .unwrap()
                .len(),
            2
        );
        let context = BTreeMap::from([
            ("service".to_owned(), "web-api".to_owned()),
            ("environment".to_owned(), "test".to_owned()),
        ]);
        let matched = v
            .resolve_scenario("client", "jenkins.build", &context)
            .unwrap();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].site, "jenkins-test");
        assert_eq!(matched[0].account, "builder");
        assert_eq!(matched[0].capability, "jenkins.build.test");
    }
}
