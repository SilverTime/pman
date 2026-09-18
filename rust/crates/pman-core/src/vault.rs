//! SQLite-backed vault compatible with the Python v2 vault format.
//!
//! The desktop UI should only use the metadata methods in this module. Secret
//! values are decrypted inside the core and are never part of a `SiteSummary`.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use chrono::Local;
use pbkdf2::pbkdf2_hmac;
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use std::{
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub const SCHEMA_VERSION: i64 = 2;
pub const SALT_BYTES: usize = 16;
pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 12;
pub const DEFAULT_KDF_ITERATIONS: u32 = 600_000;
pub const AUTH_TYPES: &[&str] = &[
    "api_token",
    "http_basic",
    "cookie_jar",
    "login",
    "password",
    "e10",
];

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("vault is already initialized")]
    AlreadyInitialized,
    #[error("vault is not initialized")]
    NotInitialized,
    #[error("vault is locked")]
    Locked,
    #[error("invalid master password")]
    InvalidPassword,
    #[error("invalid vault schema: {0}")]
    InvalidSchema(String),
    #[error("unsupported vault schema version: {0}")]
    UnsupportedSchema(i64),
    #[error("invalid site: {0}")]
    InvalidSite(String),
    #[error("site already exists: {0}")]
    DuplicateSite(String),
    #[error("unknown site: {0}")]
    UnknownSite(String),
    #[error("unknown harness: {0}")]
    UnknownHarness(String),
    #[error("site is inactive: {0}")]
    InactiveSite(String),
    #[error("unsupported auth_type: {0}")]
    UnsupportedAuthType(String),
    #[error("secret must be a non-empty JSON object")]
    InvalidSecret,
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("client identity is invalid, expired or revoked")]
    InvalidClient,
    #[error("invalid assistance request or request is outside the client's scope")]
    InvalidAssistance,
}

/// Input used when adding a site. The `secret` field stays inside pman-core.
#[derive(Clone, Serialize, Deserialize)]
pub struct SiteInput {
    pub alias: String,
    pub site_url: String,
    pub auth_type: String,
    pub secret: Value,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub login_script: Option<String>,
    #[serde(default)]
    pub refresh_on: Vec<i64>,
    #[serde(default)]
    pub requires_human: bool,
    #[serde(default)]
    pub insecure_tls: bool,
    #[serde(default)]
    pub expires_at: Option<String>,
}

impl SiteInput {
    pub fn new(
        alias: impl Into<String>,
        site_url: impl Into<String>,
        auth_type: impl Into<String>,
        secret: Value,
    ) -> Self {
        Self {
            alias: alias.into(),
            site_url: site_url.into(),
            auth_type: auth_type.into(),
            secret,
            name: None,
            purpose: None,
            tags: Vec::new(),
            login_script: None,
            refresh_on: Vec::new(),
            requires_human: false,
            insecure_tls: false,
            expires_at: None,
        }
    }
}

/// Metadata that can be edited without exposing the encrypted secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteMetadataUpdate {
    pub site_url: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Safe-to-display site metadata. Encrypted columns are intentionally absent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SiteSummary {
    pub id: String,
    pub alias: String,
    pub name: Option<String>,
    pub site_url: String,
    pub auth_type: String,
    pub purpose: Option<String>,
    pub tags: Vec<String>,
    pub login_script: Option<String>,
    pub refresh_on: Vec<i64>,
    pub requires_human: bool,
    pub insecure_tls: bool,
    pub created_at: String,
    pub updated_at: String,
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HarnessSummary {
    pub name: String,
    pub policy: Value,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEntry {
    pub id: i64,
    pub ts: String,
    pub harness: String,
    pub site: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub status_code: Option<i64>,
    pub resp_bytes: i64,
    pub redactions: i64,
    pub truncated: bool,
    pub approved: bool,
    pub req_id: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct AuditEntryInput {
    pub ts: Option<String>,
    pub harness: String,
    pub site: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub status_code: Option<i64>,
    pub resp_bytes: i64,
    pub redactions: i64,
    pub truncated: bool,
    pub approved: bool,
    pub req_id: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApprovalSummary {
    pub id: String,
    pub ts: String,
    pub harness: String,
    pub site: String,
    pub method: String,
    pub path: String,
    pub payload: Value,
    pub status: String,
    pub decided_at: Option<String>,
    pub decided_by: Option<String>,
    pub request_fingerprint: Option<String>,
    pub consumed_at: Option<String>,
}

struct EncryptedSite {
    status: String,
    dek_wrapped: Vec<u8>,
    secret_cipher: Vec<u8>,
}

pub struct Vault {
    home: PathBuf,
    db_path: PathBuf,
    pub(crate) conn: Connection,
    kek: Option<Vec<u8>>,
    generation: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl Vault {
    pub fn open(home: impl AsRef<Path>) -> Result<Self, VaultError> {
        let home = home.as_ref().to_path_buf();
        fs::create_dir_all(&home)?;
        let db_path = home.join("vault.db");
        let conn = Connection::open(&db_path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
        let mut vault = Self {
            home,
            db_path,
            conn,
            kek: None,
            generation: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        };
        vault.init_schema()?;
        vault.init_workspace_schema()?;
        vault.init_assistance_schema()?;
        vault.init_request_lifecycle()?;
        vault.recover_interrupted_requests()?;
        Ok(vault)
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn unlocked(&self) -> bool {
        self.kek.is_some()
    }

    pub fn initialized(&self) -> Result<bool, VaultError> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM meta WHERE key='master_salt' LIMIT 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some())
    }

    pub fn ensure_unlocked(&self) -> Result<(), VaultError> {
        if self.unlocked() {
            Ok(())
        } else {
            Err(VaultError::Locked)
        }
    }

    pub fn create(&mut self, password: &str) -> Result<(), VaultError> {
        if self.initialized()? {
            return Err(VaultError::AlreadyInitialized);
        }
        let salt = random_bytes::<SALT_BYTES>();
        let iterations = kdf_iterations();
        let kek = derive_kek(password, &salt, iterations)?;
        let verifier = encrypt(&kek, b"pman-ok")?;
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO meta(key,value) VALUES('schema_version',?)",
            params![SCHEMA_VERSION.to_string()],
        )?;
        tx.execute(
            "INSERT INTO meta(key,value) VALUES('master_salt',?)",
            params![hex::encode(salt)],
        )?;
        tx.execute(
            "INSERT INTO meta(key,value) VALUES('kek_verifier',?)",
            params![hex::encode(verifier)],
        )?;
        tx.execute(
            "INSERT INTO meta(key,value) VALUES('kdf_iterations',?)",
            params![iterations.to_string()],
        )?;
        tx.commit()?;
        self.kek = Some(kek);
        Ok(())
    }

    pub fn unlock(&mut self, password: &str) -> Result<(), VaultError> {
        let kek = self.password_key(password)?;
        self.kek = Some(kek.to_vec());
        if self
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key='kdf_iterations'",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .is_none()
        {
            self.conn.execute(
                "INSERT INTO meta(key,value) VALUES('kdf_iterations',?)",
                params![kdf_iterations().to_string()],
            )?;
        }
        Ok(())
    }

    /// Authenticate management without changing the background service state.
    pub fn verify_password(&self, password: &str) -> Result<(), VaultError> {
        self.password_key(password).map(|_| ())
    }

    fn password_key(&self, password: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let salt_hex: String = self
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key='master_salt'",
                [],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(VaultError::NotInitialized)?;
        let verifier_hex: String = self
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key='kek_verifier'",
                [],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| VaultError::InvalidSchema("missing kek_verifier".to_owned()))?;
        let salt = hex::decode(salt_hex)
            .map_err(|_| VaultError::InvalidSchema("invalid master_salt".to_owned()))?;
        let verifier = hex::decode(verifier_hex)
            .map_err(|_| VaultError::InvalidSchema("invalid kek_verifier".to_owned()))?;
        if salt.len() != SALT_BYTES {
            return Err(VaultError::InvalidSchema(
                "invalid master_salt length".to_owned(),
            ));
        }
        let iterations: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key='kdf_iterations'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let iterations = iterations
            .map(|v| {
                v.parse::<u32>()
                    .ok()
                    .filter(|v| *v > 0 && *v <= 10_000_000)
                    .ok_or_else(|| VaultError::InvalidSchema("invalid kdf_iterations".into()))
            })
            .transpose()?
            .unwrap_or_else(kdf_iterations);
        let kek = Zeroizing::new(derive_kek(password, &salt, iterations)?);
        match decrypt(&kek, &verifier) {
            Ok(plain) if plain == b"pman-ok" => Ok(kek),
            _ => Err(VaultError::InvalidPassword),
        }
    }

    pub fn lock(&mut self) {
        self.invalidate_requests();
        if let Some(mut kek) = self.kek.take() {
            kek.zeroize();
        }
    }

    /// Native-only material for DPAPI protection. Never serialize or log this value.
    pub fn export_resume_key(&self) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        Ok(Zeroizing::new(
            self.kek.as_ref().ok_or(VaultError::Locked)?.clone(),
        ))
    }

    pub fn resume_with_key(&mut self, key: &[u8]) -> Result<(), VaultError> {
        let verifier: String = self
            .conn
            .query_row("SELECT value FROM meta WHERE key='kek_verifier'", [], |r| {
                r.get(0)
            })
            .optional()?
            .ok_or(VaultError::NotInitialized)?;
        let verifier = hex::decode(verifier).map_err(|_| VaultError::Crypto)?;
        let plain =
            Zeroizing::new(decrypt(key, &verifier).map_err(|_| VaultError::InvalidPassword)?);
        if plain.as_slice() != b"pman-ok" {
            return Err(VaultError::InvalidPassword);
        }
        self.kek = Some(key.to_vec());
        Ok(())
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn invalidate_requests(&mut self) {
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    pub(crate) fn generation_signal(&self) -> std::sync::Arc<std::sync::atomic::AtomicU64> {
        self.generation.clone()
    }

    pub fn add_site(&mut self, input: SiteInput) -> Result<(), VaultError> {
        self.ensure_unlocked()?;
        self.invalidate_requests();
        validate_site_input(&input)?;
        let alias = input.alias.trim().to_owned();
        let exists: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM sites WHERE alias=? LIMIT 1",
                params![alias],
                |row| row.get(0),
            )
            .optional()?;
        if exists.is_some() {
            return Err(VaultError::DuplicateSite(input.alias));
        }

        let kek = self.export_resume_key()?;
        let dek = Zeroizing::new(random_bytes::<KEY_BYTES>());
        let dek_wrapped = encrypt(&kek, dek.as_ref())?;
        let secret_plain = Zeroizing::new(serde_json::to_vec(&input.secret)?);
        let secret_cipher = encrypt(dek.as_ref(), &secret_plain)?;
        let now = now();
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO sites(
                id,alias,name,site_url,auth_type,purpose,tags,login_script,refresh_on,
                requires_human,insecure_tls,dek_wrapped,secret_cipher,created_at,updated_at,expires_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                Uuid::new_v4().simple().to_string(),
                alias,
                input.name,
                input.site_url.trim_end_matches('/'),
                input.auth_type,
                input.purpose,
                serde_json::to_string(&input.tags)?,
                input.login_script,
                serde_json::to_string(&input.refresh_on)?,
                i64::from(input.requires_human),
                i64::from(input.insecure_tls),
                dek_wrapped,
                secret_cipher,
                &now,
                &now,
                input.expires_at,
            ],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO connection_details(alias,details_json) VALUES(?,?)",
            params![
                alias,
                serde_json::to_string(&crate::ConnectionDetails::default())?
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn update_secret(&mut self, alias: &str, secret: Value) -> Result<(), VaultError> {
        self.invalidate_requests();
        self.ensure_unlocked()?;
        validate_secret(&secret)?;
        let row = self.encrypted_site(alias)?;
        if row.status != "active" {
            return Err(VaultError::InactiveSite(alias.to_owned()));
        }
        let kek = self.export_resume_key()?;
        let dek = Zeroizing::new(decrypt(&kek, &row.dek_wrapped)?);
        let plain = Zeroizing::new(serde_json::to_vec(&secret)?);
        let cipher = encrypt(&dek, &plain)?;
        self.conn.execute(
            "UPDATE sites SET secret_cipher=?, updated_at=? WHERE alias=?",
            params![cipher, now(), alias],
        )?;
        Ok(())
    }

    /// Merge a user-provided secret patch inside the unlocked core.
    /// Existing secret values never leave the core and are never returned to the UI.
    pub fn rotate_secret(&mut self, alias: &str, patch: Value) -> Result<(), VaultError> {
        self.ensure_unlocked()?;
        let patch_object = patch.as_object().ok_or(VaultError::InvalidSecret)?;
        if patch_object.is_empty() {
            return Err(VaultError::InvalidSecret);
        }
        let mut current = self.get_site_secret(alias)?;
        let current_object = current.as_object_mut().ok_or(VaultError::InvalidSecret)?;
        for (key, value) in patch_object {
            if value.is_null() {
                current_object.remove(key);
            } else {
                current_object.insert(key.clone(), value.clone());
            }
        }
        self.update_secret(alias, current)
    }

    pub fn update_site_metadata(
        &mut self,
        alias: &str,
        input: SiteMetadataUpdate,
    ) -> Result<(), VaultError> {
        self.ensure_unlocked()?;
        self.invalidate_requests();
        let site_url = input.site_url.trim().trim_end_matches('/').to_owned();
        let previous = self
            .list_sites()?
            .into_iter()
            .find(|s| s.alias == alias)
            .ok_or_else(|| VaultError::UnknownSite(alias.into()))?;
        let password_only = previous.auth_type == "password";
        validate_site_url(&site_url, password_only)?;
        if previous.site_url != site_url {
            self.revoke_connection_grants(alias)?;
            self.update_details(alias, serde_json::json!({"ai_enabled":false}))?;
        }
        let name = input.name.and_then(|value| {
            let value = value.trim().to_owned();
            if value.is_empty() {
                None
            } else {
                Some(value)
            }
        });
        let purpose = input.purpose.and_then(|value| {
            let value = value.trim().to_owned();
            if value.is_empty() {
                None
            } else {
                Some(value)
            }
        });
        let tags: Vec<String> = input
            .tags
            .into_iter()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .collect();
        let changed = self.conn.execute(
            "UPDATE sites SET site_url=?, name=?, purpose=?, tags=?, updated_at=? WHERE alias=?",
            params![
                site_url,
                name,
                purpose,
                serde_json::to_string(&tags)?,
                now(),
                alias
            ],
        )?;
        if changed == 0 {
            return Err(VaultError::UnknownSite(alias.to_owned()));
        }
        Ok(())
    }

    /// Decrypt a secret for use by the broker. Do not serialize this value to UI/MCP.
    pub fn get_site_secret(&self, alias: &str) -> Result<Value, VaultError> {
        self.ensure_unlocked()?;
        let row = self.encrypted_site(alias)?;
        if row.status != "active" {
            return Err(VaultError::InactiveSite(alias.to_owned()));
        }
        let kek = self.kek.as_ref().ok_or(VaultError::Locked)?;
        let dek = Zeroizing::new(decrypt(kek, &row.dek_wrapped).map_err(|_| VaultError::Crypto)?);
        let plain =
            Zeroizing::new(decrypt(&dek, &row.secret_cipher).map_err(|_| VaultError::Crypto)?);
        let value: Value = serde_json::from_slice(&plain)?;
        validate_secret(&value)?;
        Ok(value)
    }

    pub fn list_sites(&self) -> Result<Vec<SiteSummary>, VaultError> {
        let mut stmt = self.conn.prepare(
            "SELECT id,alias,name,site_url,auth_type,purpose,tags,login_script,refresh_on,
                    requires_human,insecure_tls,created_at,updated_at,last_used_at,expires_at,status
             FROM sites ORDER BY alias",
        )?;
        let rows = stmt.query_map([], |row| {
            let tags: String = row.get(6)?;
            let refresh_on: String = row.get(8)?;
            Ok(SiteSummary {
                id: row.get(0)?,
                alias: row.get(1)?,
                name: row.get(2)?,
                site_url: row.get(3)?,
                auth_type: row.get(4)?,
                purpose: row.get(5)?,
                tags: serde_json::from_str(&tags).unwrap_or_default(),
                login_script: row.get(7)?,
                refresh_on: serde_json::from_str(&refresh_on).unwrap_or_default(),
                requires_human: row.get::<_, i64>(9)? != 0,
                insecure_tls: row.get::<_, i64>(10)? != 0,
                created_at: row.get(11)?,
                updated_at: row.get(12)?,
                last_used_at: row.get(13)?,
                expires_at: row.get(14)?,
                status: row.get(15)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(VaultError::from)
    }

    pub fn remove_site(&mut self, alias: &str) -> Result<(), VaultError> {
        self.ensure_unlocked()?;
        self.revoke_connection_grants(alias)?;
        self.invalidate_requests();
        self.conn
            .execute("DELETE FROM connection_details WHERE alias=?", [alias])?;
        let tx = self.conn.transaction()?;
        let exists: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM sites WHERE alias=? LIMIT 1",
                params![alias],
                |row| row.get(0),
            )
            .optional()?;
        if exists.is_none() {
            return Err(VaultError::UnknownSite(alias.to_owned()));
        }

        let policies: Vec<(String, String)> = {
            let mut statement = tx.prepare("SELECT name, policy_json FROM harnesses")?;
            let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        for (name, policy_json) in policies {
            let Ok(mut policy) = serde_json::from_str::<Value>(&policy_json) else {
                continue;
            };
            let Some(allow) = policy.get_mut("allow").and_then(Value::as_array_mut) else {
                continue;
            };
            let before = allow.len();
            allow.retain(|rule| rule.get("site").and_then(Value::as_str) != Some(alias));
            if allow.len() != before {
                tx.execute(
                    "UPDATE harnesses SET policy_json=? WHERE name=?",
                    params![serde_json::to_string(&policy)?, name],
                )?;
            }
        }

        let changed = tx.execute("DELETE FROM sites WHERE alias=?", params![alias])?;
        if changed == 0 {
            return Err(VaultError::UnknownSite(alias.to_owned()));
        }
        tx.commit()?;
        Ok(())
    }

    pub fn touch_site(&mut self, alias: &str) -> Result<(), VaultError> {
        let changed = self.conn.execute(
            "UPDATE sites SET last_used_at=? WHERE alias=?",
            params![now(), alias],
        )?;
        if changed == 0 {
            return Err(VaultError::UnknownSite(alias.to_owned()));
        }
        Ok(())
    }

    pub fn get_harness(&self, name: &str) -> Result<Option<HarnessSummary>, VaultError> {
        self.conn
            .query_row(
                "SELECT name,policy_json,created_at,expires_at,revoked_at FROM harnesses WHERE name=?",
                params![name],
                |row| {
                    let policy_json: String = row.get(1)?;
                    Ok(HarnessSummary {
                        name: row.get(0)?,
                        policy: serde_json::from_str(&policy_json).unwrap_or_else(|_| serde_json::json!({"default_action":"deny","allow": []})),
                        created_at: row.get(2)?,
                        expires_at: row.get(3)?,
                        revoked_at: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(VaultError::from)
    }

    /// Create a local harness profile without issuing a bearer token.
    pub fn ensure_harness(&mut self, name: &str) -> Result<HarnessSummary, VaultError> {
        self.ensure_unlocked()?;
        if name.trim().is_empty() || name.chars().count() > 128 {
            return Err(VaultError::InvalidSite(
                "harness name must be 1-128 characters".to_owned(),
            ));
        }
        if let Some(harness) = self.get_harness(name)? {
            return Ok(harness);
        }
        let now = now();
        self.conn.execute(
            "INSERT INTO harnesses(id,name,policy_json,created_at) VALUES(?,?,?,?)",
            params![
                Uuid::new_v4().simple().to_string(),
                name.trim(),
                "{\"default_action\":\"deny\",\"allow\": []}",
                &now
            ],
        )?;
        self.get_harness(name)?
            .ok_or_else(|| VaultError::UnknownHarness(name.to_owned()))
    }

    /// Permanently remove a local harness profile while retaining audit history.
    /// Any pending approvals for the removed identity are denied so they cannot
    /// be approved after the profile has gone away.
    pub fn delete_harness(&mut self, name: &str) -> Result<(), VaultError> {
        self.invalidate_requests();
        self.ensure_unlocked()?;
        if self.get_harness(name)?.is_none() {
            return Err(VaultError::UnknownHarness(name.to_owned()));
        }
        let decided_at = now();
        self.conn.execute("UPDATE assistance_requests SET status='cancelled',updated_at=? WHERE harness=? AND status='pending'",params![decided_at,name])?;
        self.conn.execute(
            "UPDATE approvals SET status='denied',decided_at=?,decided_by=? WHERE harness=? AND status='pending'",
            params![decided_at, "harness-deleted", name],
        )?;
        let changed = self
            .conn
            .execute("DELETE FROM harnesses WHERE name=?", params![name])?;
        if changed == 0 {
            return Err(VaultError::UnknownHarness(name.to_owned()));
        }
        Ok(())
    }

    pub fn list_harnesses(&self) -> Result<Vec<HarnessSummary>, VaultError> {
        let mut stmt = self.conn.prepare(
            "SELECT name,policy_json,created_at,expires_at,revoked_at FROM harnesses ORDER BY name",
        )?;
        let rows = stmt.query_map([], |row| {
            let policy_json: String = row.get(1)?;
            Ok(HarnessSummary {
                name: row.get(0)?,
                policy: serde_json::from_str(&policy_json)
                    .unwrap_or_else(|_| serde_json::json!({"default_action":"deny","allow": []})),
                created_at: row.get(2)?,
                expires_at: row.get(3)?,
                revoked_at: row.get(4)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(VaultError::from)
    }

    pub fn set_policy(&mut self, name: &str, policy: Value) -> Result<(), VaultError> {
        self.invalidate_requests();
        self.ensure_unlocked()?;
        if !policy.is_object() {
            return Err(VaultError::InvalidSchema(
                "harness policy must be a JSON object".to_owned(),
            ));
        }
        crate::Policy::from_json(&policy)
            .map_err(|error| VaultError::InvalidSchema(error.to_string()))?;
        let changed = self.conn.execute(
            "UPDATE harnesses SET policy_json=? WHERE name=?",
            params![serde_json::to_string(&policy)?, name],
        )?;
        if changed == 0 {
            return Err(VaultError::UnknownHarness(name.to_owned()));
        }
        Ok(())
    }

    /// Append one exact allow rule while preserving the rest of the policy.
    /// This is used by the desktop's explicit human-confirmation flows so a
    /// user does not need to hand-edit the full JSON document.
    pub fn add_allow_rule(
        &mut self,
        name: &str,
        site: &str,
        method: &str,
        path: &str,
    ) -> Result<HarnessSummary, VaultError> {
        self.ensure_unlocked()?;
        let site = site.trim();
        let method = method.trim().to_ascii_uppercase();
        let path = path.trim();
        if site.is_empty() || site.chars().count() > 128 {
            return Err(VaultError::InvalidSite(
                "allow rule site must be 1-128 characters".to_owned(),
            ));
        }
        if !matches!(
            method.as_str(),
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
        ) {
            return Err(VaultError::InvalidSchema(
                "allow rule method is not supported".to_owned(),
            ));
        }
        if path.is_empty() || !path.starts_with('/') || path.contains('?') || path.contains('#') {
            return Err(VaultError::InvalidSchema(
                "allow rule path must be an absolute path without query or fragment".to_owned(),
            ));
        }
        let mut policy = self.get_policy(name)?;
        let object = policy.as_object_mut().ok_or_else(|| {
            VaultError::InvalidSchema("harness policy must be a JSON object".to_owned())
        })?;
        let allow = object
            .entry("allow".to_owned())
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .ok_or_else(|| {
                VaultError::InvalidSchema("harness policy allow must be an array".to_owned())
            })?;
        let duplicate = allow.iter().any(|rule| {
            rule.get("site").and_then(Value::as_str) == Some(site)
                && rule
                    .get("methods")
                    .and_then(Value::as_array)
                    .is_some_and(|methods| {
                        methods.iter().any(|item| {
                            item.as_str()
                                .is_some_and(|item| item.eq_ignore_ascii_case(&method))
                        })
                    })
                && rule
                    .get("paths")
                    .and_then(Value::as_array)
                    .is_some_and(|paths| paths.iter().any(|item| item.as_str() == Some(path)))
        });
        if !duplicate {
            allow.push(serde_json::json!({"site": site, "methods": [method], "paths": [path]}));
            self.set_policy(name, policy)?;
        }
        self.get_harness(name)?
            .ok_or_else(|| VaultError::UnknownHarness(name.to_owned()))
    }

    /// Remove one previously saved allow rule without changing the rest of the policy.
    /// The complete JSON rule is used as the selector so a stale UI cannot silently
    /// remove a different rule after the policy has changed.
    pub fn remove_allow_rule(
        &mut self,
        name: &str,
        target: Value,
    ) -> Result<HarnessSummary, VaultError> {
        self.ensure_unlocked()?;
        if !target.is_object() {
            return Err(VaultError::InvalidSchema(
                "allow rule must be a JSON object".to_owned(),
            ));
        }
        let mut policy = self.get_policy(name)?;
        let object = policy.as_object_mut().ok_or_else(|| {
            VaultError::InvalidSchema("harness policy must be a JSON object".to_owned())
        })?;
        let allow = object
            .get_mut("allow")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| {
                VaultError::InvalidSchema("harness policy allow must be an array".to_owned())
            })?;
        let index = allow
            .iter()
            .position(|rule| rule == &target)
            .ok_or_else(|| {
                VaultError::InvalidSchema(
                    "allow rule was not found; reload the policy and try again".to_owned(),
                )
            })?;
        allow.remove(index);
        self.set_policy(name, policy)?;
        self.get_harness(name)?
            .ok_or_else(|| VaultError::UnknownHarness(name.to_owned()))
    }

    pub fn get_policy(&self, name: &str) -> Result<Value, VaultError> {
        self.get_harness(name)?
            .map(|harness| harness.policy)
            .ok_or_else(|| VaultError::UnknownHarness(name.to_owned()))
    }

    pub fn add_audit(&mut self, entry: &AuditEntryInput) -> Result<(), VaultError> {
        let ts = entry.ts.clone().unwrap_or_else(now);
        self.conn.execute(
            "INSERT INTO audit_log(
                ts,harness,site,method,path,status_code,resp_bytes,redactions,truncated,approved,req_id,note
             ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                ts,
                &entry.harness,
                &entry.site,
                &entry.method,
                &entry.path,
                entry.status_code,
                entry.resp_bytes,
                entry.redactions,
                i64::from(entry.truncated),
                i64::from(entry.approved),
                &entry.req_id,
                &entry.note,
            ],
        )?;
        Ok(())
    }

    pub fn query_audit(
        &self,
        harness: Option<&str>,
        limit: i64,
    ) -> Result<Vec<AuditEntry>, VaultError> {
        let limit = limit.clamp(1, 1000);
        let mut entries = Vec::new();
        if let Some(harness) = harness {
            let mut stmt = self.conn.prepare(
                "SELECT id,ts,harness,site,method,path,status_code,resp_bytes,redactions,truncated,approved,req_id,note
                 FROM audit_log WHERE harness=? ORDER BY id DESC LIMIT ?",
            )?;
            let rows = stmt.query_map(params![harness, limit], audit_from_row)?;
            for row in rows {
                entries.push(row?);
            }
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT id,ts,harness,site,method,path,status_code,resp_bytes,redactions,truncated,approved,req_id,note
                 FROM audit_log ORDER BY id DESC LIMIT ?",
            )?;
            let rows = stmt.query_map(params![limit], audit_from_row)?;
            for row in rows {
                entries.push(row?);
            }
        }
        Ok(entries)
    }

    pub fn create_approval(
        &mut self,
        harness: &str,
        site: &str,
        method: &str,
        path: &str,
        payload: &Value,
        request_fingerprint: Option<&str>,
    ) -> Result<String, VaultError> {
        self.ensure_unlocked()?;
        let id = format!("apr_{}", &Uuid::new_v4().simple().to_string()[..12]);
        self.conn.execute(
            "INSERT INTO approvals(id,ts,harness,site,method,path,payload,status,request_fingerprint)
             VALUES(?,?,?,?,?,?,?,'pending',?)",
            params![id, now(), harness, site, method, path, serde_json::to_string(payload)?, request_fingerprint],
        )?;
        Ok(id)
    }

    pub fn get_approval(&self, id: &str) -> Result<Option<ApprovalSummary>, VaultError> {
        self.conn
            .query_row(
                "SELECT id,ts,harness,site,method,path,payload,status,decided_at,decided_by,request_fingerprint,consumed_at
                 FROM approvals WHERE id=?",
                params![id],
                approval_from_row,
            )
            .optional()
            .map_err(VaultError::from)
    }

    pub fn list_approvals(&self, status: &str) -> Result<Vec<ApprovalSummary>, VaultError> {
        let mut stmt = self.conn.prepare(
            "SELECT id,ts,harness,site,method,path,payload,status,decided_at,decided_by,request_fingerprint,consumed_at
             FROM approvals WHERE status=? ORDER BY ts DESC",
        )?;
        let rows = stmt.query_map(params![status], approval_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(VaultError::from)
    }

    pub fn decide_approval(
        &mut self,
        id: &str,
        approve: bool,
        decided_by: &str,
    ) -> Result<Option<ApprovalSummary>, VaultError> {
        let Some(current) = self.get_approval(id)? else {
            return Ok(None);
        };
        if current.status != "pending" {
            return Ok(Some(current));
        }
        self.conn.execute(
            "UPDATE approvals SET status=?,decided_at=?,decided_by=? WHERE id=?",
            params![
                if approve { "approved" } else { "denied" },
                now(),
                decided_by,
                id
            ],
        )?;
        self.get_approval(id)
    }

    /// Turn a pending request into a durable, revocable policy rule.
    ///
    /// The rule is deliberately bound to the approval's harness, connection,
    /// method and exact path. Query parameters and request bodies may change,
    /// but explicit deny rules continue to take precedence. The approval is
    /// marked consumed so it can never also act as a one-shot grant.
    pub fn approve_persistently(
        &mut self,
        id: &str,
        decided_by: &str,
    ) -> Result<Option<ApprovalSummary>, VaultError> {
        self.ensure_unlocked()?;
        let Some(current) = self.get_approval(id)? else {
            return Ok(None);
        };
        if current.status != "pending" {
            return Ok(Some(current));
        }

        let mut policy = self.get_policy(&current.harness)?;
        let object = policy.as_object_mut().ok_or_else(|| {
            VaultError::InvalidSchema("harness policy must be a JSON object".to_owned())
        })?;
        let allow = object
            .entry("allow".to_owned())
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .ok_or_else(|| {
                VaultError::InvalidSchema("harness policy allow must be an array".to_owned())
            })?;
        let duplicate = allow.iter().any(|rule| {
            rule.get("site").and_then(Value::as_str) == Some(current.site.as_str())
                && rule.get("capability").and_then(Value::as_str)
                    == current.payload.get("capability").and_then(Value::as_str)
                && rule.get("require_approval").and_then(Value::as_bool) == Some(false)
                && rule
                    .get("methods")
                    .and_then(Value::as_array)
                    .is_some_and(|methods| {
                        methods.iter().any(|item| {
                            item.as_str().is_some_and(|item| {
                                item.eq_ignore_ascii_case(current.method.as_str())
                            })
                        })
                    })
                && rule
                    .get("paths")
                    .and_then(Value::as_array)
                    .is_some_and(|paths| {
                        paths
                            .iter()
                            .any(|item| item.as_str() == Some(current.path.as_str()))
                    })
        });
        if !duplicate {
            let operation = if matches!(
                current.method.to_ascii_uppercase().as_str(),
                "GET" | "HEAD" | "OPTIONS"
            ) {
                "query"
            } else {
                "write"
            };
            allow.push(serde_json::json!({
                "site": current.site,
                "methods": [current.method.to_ascii_uppercase()],
                "paths": [current.path],
                "capability": current.payload.get("capability").cloned().unwrap_or(Value::Null),
                "operation": operation,
                "require_approval": false
            }));
        }
        crate::Policy::from_json(&policy)
            .map_err(|error| VaultError::InvalidSchema(error.to_string()))?;

        let timestamp = now();
        let transaction = self.conn.transaction()?;
        let harness_changed = transaction.execute(
            "UPDATE harnesses SET policy_json=? WHERE name=?",
            params![serde_json::to_string(&policy)?, &current.harness],
        )?;
        if harness_changed == 0 {
            return Err(VaultError::UnknownHarness(current.harness));
        }
        let approval_changed = transaction.execute(
            "UPDATE approvals
             SET status='approved',decided_at=?,decided_by=?,consumed_at=?
             WHERE id=? AND status='pending'",
            params![&timestamp, decided_by, &timestamp, id],
        )?;
        if approval_changed == 0 {
            transaction.rollback()?;
            return self.get_approval(id);
        }
        transaction.commit()?;
        self.invalidate_requests();
        self.get_approval(id)
    }

    pub fn consume_approval(&mut self, id: &str) -> Result<bool, VaultError> {
        let changed = self.conn.execute(
            "UPDATE approvals SET consumed_at=? WHERE id=? AND status='approved' AND consumed_at IS NULL",
            params![now(), id],
        )?;
        Ok(changed == 1)
    }

    pub fn consume_recent_approval(
        &mut self,
        harness: &str,
        site: &str,
        method: &str,
        path: &str,
        fingerprint: &str,
        within_seconds: i64,
    ) -> Result<bool, VaultError> {
        let cutoff = Local::now()
            .checked_sub_signed(chrono::Duration::seconds(within_seconds.max(0)))
            .unwrap_or_else(Local::now)
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string();
        let id: Option<String> = self
            .conn
            .query_row(
                "SELECT id FROM approvals
                 WHERE harness=? AND site=? AND method=? AND path=? AND request_fingerprint=?
                   AND status='approved' AND decided_at>=? AND consumed_at IS NULL
                 ORDER BY decided_at DESC LIMIT 1",
                params![harness, site, method, path, fingerprint, cutoff],
                |row| row.get(0),
            )
            .optional()?;
        let Some(id) = id else {
            return Ok(false);
        };
        self.consume_approval(&id)
    }

    pub fn approval_fingerprint(
        &self,
        site: &str,
        method: &str,
        path: &str,
        capability: Option<&str>,
        query: Option<&Value>,
        json_body: Option<&Value>,
        form: Option<&Value>,
    ) -> Result<String, VaultError> {
        use hmac::{Hmac, Mac};
        self.ensure_unlocked()?;
        let canonical = serde_json::to_vec(&serde_json::json!({
            "site": site,
            "method": method.to_ascii_uppercase(),
            "path": path,
            "capability": capability,
            "query": query,
            "json_body": json_body,
            "form": form,
        }))?;
        let key = self.kek.as_ref().ok_or(VaultError::Locked)?;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| VaultError::Crypto)?;
        mac.update(&canonical);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    fn encrypted_site(&self, alias: &str) -> Result<EncryptedSite, VaultError> {
        self.conn
            .query_row(
                "SELECT status,dek_wrapped,secret_cipher FROM sites WHERE alias=?",
                params![alias],
                |row| {
                    Ok(EncryptedSite {
                        status: row.get(0)?,
                        dek_wrapped: row.get(1)?,
                        secret_cipher: row.get(2)?,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| VaultError::UnknownSite(alias.to_owned()))
    }

    fn init_schema(&mut self) -> Result<(), VaultError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (
                 key TEXT PRIMARY KEY, value TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS sites (
                 id TEXT PRIMARY KEY, alias TEXT NOT NULL UNIQUE, name TEXT,
                 site_url TEXT NOT NULL, auth_type TEXT NOT NULL, purpose TEXT,
                 tags TEXT, login_script TEXT, refresh_on TEXT,
                 requires_human INTEGER NOT NULL DEFAULT 0,
                 insecure_tls INTEGER NOT NULL DEFAULT 0,
                 dek_wrapped BLOB, secret_cipher BLOB,
                 created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                 last_used_at TEXT, expires_at TEXT,
                 status TEXT NOT NULL DEFAULT 'active'
             );
             CREATE TABLE IF NOT EXISTS harnesses (
                 id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
             token_hash TEXT, policy_json TEXT NOT NULL DEFAULT '{\"default_action\":\"deny\",\"allow\": []}',
                 created_at TEXT NOT NULL, expires_at TEXT, revoked_at TEXT
             );
             CREATE TABLE IF NOT EXISTS audit_log (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
                 harness TEXT NOT NULL, site TEXT, method TEXT, path TEXT,
                 status_code INTEGER, resp_bytes INTEGER NOT NULL DEFAULT 0,
                 redactions INTEGER NOT NULL DEFAULT 0,
                 truncated INTEGER NOT NULL DEFAULT 0,
                 approved INTEGER NOT NULL DEFAULT 0, req_id TEXT, note TEXT
             );
             CREATE TABLE IF NOT EXISTS approvals (
                 id TEXT PRIMARY KEY, ts TEXT NOT NULL, harness TEXT NOT NULL,
                 site TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL,
                 payload TEXT, status TEXT NOT NULL DEFAULT 'pending',
                 decided_at TEXT, decided_by TEXT,
                 request_fingerprint TEXT, consumed_at TEXT
             );
             CREATE TABLE IF NOT EXISTS leases (
                 id TEXT PRIMARY KEY, harness TEXT NOT NULL,
                 token_hash TEXT NOT NULL, note TEXT, created_at TEXT NOT NULL,
                 expires_at TEXT NOT NULL, revoked_at TEXT, last_used_at TEXT
             );
             CREATE INDEX IF NOT EXISTS idx_leases_token_hash ON leases(token_hash);",
        )?;

        let columns: Vec<String> = {
            let mut stmt = self.conn.prepare("PRAGMA table_info(approvals)")?;
            let mapped = stmt.query_map([], |row| row.get(1))?;
            mapped.collect::<Result<Vec<String>, _>>()?
        };
        if !columns.iter().any(|name| name == "request_fingerprint") {
            self.conn.execute(
                "ALTER TABLE approvals ADD COLUMN request_fingerprint TEXT",
                [],
            )?;
        }
        if !columns.iter().any(|name| name == "consumed_at") {
            self.conn
                .execute("ALTER TABLE approvals ADD COLUMN consumed_at TEXT", [])?;
        }

        let version: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key='schema_version'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(version) = version {
            let version = version.parse::<i64>().map_err(|_| {
                VaultError::InvalidSchema("schema_version must be an integer".to_owned())
            })?;
            if version > SCHEMA_VERSION {
                return Err(VaultError::UnsupportedSchema(version));
            }
            if version < SCHEMA_VERSION {
                self.conn.execute(
                    "UPDATE meta SET value=? WHERE key='schema_version'",
                    params![SCHEMA_VERSION.to_string()],
                )?;
            }
        }
        Ok(())
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.lock();
    }
}

fn audit_from_row(row: &Row<'_>) -> rusqlite::Result<AuditEntry> {
    Ok(AuditEntry {
        id: row.get(0)?,
        ts: row.get(1)?,
        harness: row.get(2)?,
        site: row.get(3)?,
        method: row.get(4)?,
        path: row.get(5)?,
        status_code: row.get(6)?,
        resp_bytes: row.get(7)?,
        redactions: row.get(8)?,
        truncated: row.get::<_, i64>(9)? != 0,
        approved: row.get::<_, i64>(10)? != 0,
        req_id: row.get(11)?,
        note: row.get(12)?,
    })
}

fn approval_from_row(row: &Row<'_>) -> rusqlite::Result<ApprovalSummary> {
    let payload: Option<String> = row.get(6)?;
    Ok(ApprovalSummary {
        id: row.get(0)?,
        ts: row.get(1)?,
        harness: row.get(2)?,
        site: row.get(3)?,
        method: row.get(4)?,
        path: row.get(5)?,
        payload: payload
            .as_deref()
            .and_then(|value| serde_json::from_str(value).ok())
            .unwrap_or_else(|| serde_json::json!({})),
        status: row.get(7)?,
        decided_at: row.get(8)?,
        decided_by: row.get(9)?,
        request_fingerprint: row.get(10)?,
        consumed_at: row.get(11)?,
    })
}

fn validate_site_input(input: &SiteInput) -> Result<(), VaultError> {
    let alias = input.alias.trim();
    if alias.is_empty() || alias.chars().count() > 128 {
        return Err(VaultError::InvalidSite(
            "alias must be 1-128 characters".to_owned(),
        ));
    }
    validate_site_url(&input.site_url, input.auth_type == "password")?;
    if !AUTH_TYPES.contains(&input.auth_type.as_str()) {
        return Err(VaultError::UnsupportedAuthType(input.auth_type.clone()));
    }
    validate_secret(&input.secret)
}

fn validate_secret(secret: &Value) -> Result<(), VaultError> {
    match secret {
        Value::Object(map) if !map.is_empty() => Ok(()),
        _ => Err(VaultError::InvalidSecret),
    }
}

fn validate_site_url(raw: &str, allow_empty: bool) -> Result<(), VaultError> {
    if allow_empty && raw.trim().is_empty() {
        return Ok(());
    }
    let url = url::Url::parse(raw.trim())
        .map_err(|_| VaultError::InvalidSite("Valid HTTP or HTTPS base URL required".into()))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(VaultError::InvalidSite(
            "Base URL cannot contain credentials, query or fragment".into(),
        ));
    }
    Ok(())
}

pub(crate) fn now() -> String {
    Local::now().format("%Y-%m-%dT%H:%M:%S").to_string()
}

pub(crate) fn is_expired(value: Option<&str>) -> bool {
    let Some(value) = value else { return false };
    if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(value) {
        return parsed <= chrono::Utc::now();
    }
    chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S")
        .map(|parsed| parsed <= Local::now().naive_local())
        .unwrap_or(true)
}

fn kdf_iterations() -> u32 {
    std::env::var("PM_KDF_ITERATIONS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_KDF_ITERATIONS)
}

pub(crate) fn derive_kek(
    password: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<Vec<u8>, VaultError> {
    if password.is_empty() {
        return Err(VaultError::InvalidPassword);
    }
    let mut key = [0_u8; KEY_BYTES];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut key);
    Ok(key.to_vec())
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0_u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub(crate) fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| VaultError::Crypto)?;
    let nonce_bytes = random_bytes::<NONCE_BYTES>();
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| VaultError::Crypto)?;
    let mut payload = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&ciphertext);
    Ok(payload)
}

pub(crate) fn decrypt(key: &[u8], payload: &[u8]) -> Result<Vec<u8>, VaultError> {
    if payload.len() < NONCE_BYTES + 16 {
        return Err(VaultError::Crypto);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| VaultError::Crypto)?;
    cipher
        .decrypt(
            Nonce::from_slice(&payload[..NONCE_BYTES]),
            &payload[NONCE_BYTES..],
        )
        .map_err(|_| VaultError::Crypto)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn creates_unlocks_and_round_trips_site_secret() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut vault = Vault::open(temp.path()).expect("open");
        vault.create("master-pw").expect("create");
        vault
            .add_site(SiteInput::new(
                "gitlab",
                "https://git.local/",
                "api_token",
                json!({"token": "secret-token"}),
            ))
            .expect("add site");

        let sites = vault.list_sites().expect("list");
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].site_url, "https://git.local");
        assert_eq!(
            vault.get_site_secret("gitlab").expect("secret"),
            json!({"token": "secret-token"})
        );

        vault.lock();
        assert!(!vault.unlocked());
        assert!(matches!(
            vault.get_site_secret("gitlab"),
            Err(VaultError::Locked)
        ));
        assert!(matches!(
            vault.unlock("wrong"),
            Err(VaultError::InvalidPassword)
        ));
        vault.unlock("master-pw").expect("unlock");
        assert_eq!(
            vault.get_site_secret("gitlab").expect("secret"),
            json!({"token": "secret-token"})
        );
    }

    #[test]
    fn edits_metadata_rotates_secret_and_cleans_site_policy_rules() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut vault = Vault::open(temp.path()).expect("open");
        vault.create("pw").expect("create");
        vault
            .add_site(SiteInput::new(
                "gitlab",
                "https://git.local/",
                "api_token",
                json!({"token": "old-token", "header": "Private-Token"}),
            ))
            .expect("add site");
        vault
            .update_site_metadata(
                "gitlab",
                SiteMetadataUpdate {
                    site_url: "https://git.example/".to_owned(),
                    name: Some("Release GitLab".to_owned()),
                    purpose: Some("发布流水线".to_owned()),
                    tags: vec!["release".to_owned()],
                },
            )
            .expect("metadata");
        vault
            .rotate_secret("gitlab", json!({"token": "new-token"}))
            .expect("rotate");
        let site = &vault.list_sites().expect("list")[0];
        assert_eq!(site.site_url, "https://git.example");
        assert_eq!(site.name.as_deref(), Some("Release GitLab"));
        assert_eq!(site.tags, vec!["release"]);
        assert_eq!(
            vault.get_site_secret("gitlab").expect("secret"),
            json!({"token": "new-token", "header": "Private-Token"})
        );

        vault.ensure_harness("codex").expect("harness");
        vault
            .add_allow_rule("codex", "gitlab", "GET", "/api/**")
            .expect("allow");
        vault.remove_site("gitlab").expect("remove");
        assert!(vault.list_sites().expect("list").is_empty());
        let harness = vault
            .get_harness("codex")
            .expect("lookup")
            .expect("harness");
        assert_eq!(harness.policy["allow"].as_array().expect("allow").len(), 0);
    }

    #[test]
    fn appends_exact_allow_rule_without_duplicates() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut vault = Vault::open(temp.path()).expect("open");
        vault.create("pw").expect("create");
        vault.ensure_harness("codex").expect("harness");
        let first = vault
            .add_allow_rule("codex", "gitlab", "get", "/api/version")
            .expect("first rule");
        assert_eq!(first.policy["allow"].as_array().expect("allow").len(), 1);
        let second = vault
            .add_allow_rule("codex", "gitlab", "GET", "/api/version")
            .expect("duplicate rule");
        assert_eq!(second.policy["allow"].as_array().expect("allow").len(), 1);
        assert!(vault
            .add_allow_rule("codex", "gitlab", "TRACE", "/api/version")
            .is_err());
        assert!(vault
            .add_allow_rule("codex", "gitlab", "GET", "api/version")
            .is_err());
    }

    #[test]
    fn removes_only_the_selected_allow_rule() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut vault = Vault::open(temp.path()).expect("open");
        vault.create("pw").expect("create");
        vault.ensure_harness("codex").expect("harness");
        let first = vault
            .add_allow_rule("codex", "gitlab", "GET", "/api/version")
            .expect("first rule");
        let second = vault
            .add_allow_rule("codex", "gitlab", "POST", "/api/issues")
            .expect("second rule");
        let target = first.policy["allow"][0].clone();

        let updated = vault
            .remove_allow_rule("codex", target.clone())
            .expect("remove rule");
        let rules = updated.policy["allow"].as_array().expect("allow");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0], second.policy["allow"][1]);
        assert!(vault.remove_allow_rule("codex", target).is_err());
    }

    #[test]
    fn deletes_harness_but_keeps_audit_history_and_denies_pending_approvals() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut vault = Vault::open(temp.path()).expect("open");
        vault.create("pw").expect("create");
        vault.ensure_harness("test").expect("harness");
        let approval_id = vault
            .create_approval("test", "gitlab", "GET", "/api/version", &json!({}), None)
            .expect("approval");
        vault
            .add_audit(&AuditEntryInput {
                harness: "test".to_owned(),
                site: Some("gitlab".to_owned()),
                method: Some("GET".to_owned()),
                path: Some("/api/version".to_owned()),
                status_code: Some(403),
                resp_bytes: 0,
                redactions: 0,
                truncated: false,
                approved: false,
                req_id: None,
                note: Some("policy denied".to_owned()),
                ts: None,
            })
            .expect("audit");

        vault.delete_harness("test").expect("delete harness");
        assert!(vault.get_harness("test").expect("lookup").is_none());
        assert_eq!(vault.list_approvals("pending").expect("pending").len(), 0);
        assert_eq!(
            vault
                .get_approval(&approval_id)
                .expect("approval")
                .expect("row")
                .status,
            "denied"
        );
        assert_eq!(vault.query_audit(Some("test"), 10).expect("audit").len(), 1);
        assert!(vault.delete_harness("test").is_err());
    }

    #[test]
    fn migrates_schema_version_one_without_rewriting_ciphertext() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut vault = Vault::open(temp.path()).expect("open");
        vault.create("master-pw").expect("create");
        vault
            .conn
            .execute("UPDATE meta SET value='1' WHERE key='schema_version'", [])
            .expect("downgrade marker");
        drop(vault);

        let reopened = Vault::open(temp.path()).expect("reopen");
        let version: String = reopened
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key='schema_version'",
                [],
                |row| row.get(0),
            )
            .expect("schema version");
        assert_eq!(version, "2");
    }

    #[test]
    fn one_shot_approval_fingerprint_is_bound_to_capability() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut vault = Vault::open(temp.path()).expect("open");
        vault.create("master-pw").expect("create");
        let build = vault
            .approval_fingerprint(
                "jenkins",
                "POST",
                "/build",
                Some("jenkins.build.test"),
                None,
                None,
                None,
            )
            .expect("build fingerprint");
        let release = vault
            .approval_fingerprint(
                "jenkins",
                "POST",
                "/build",
                Some("jenkins.release"),
                None,
                None,
                None,
            )
            .expect("release fingerprint");
        assert_ne!(build, release);
    }
}
