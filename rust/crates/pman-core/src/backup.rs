//! Whole-archive encryption. Machine unlock material and pairing capability files are never exported.
use crate::{Vault, VaultError};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
struct Archive {
    format: String,
    version: u32,
    salt: String,
    kdf_iterations: u32,
    ciphertext: String,
}
const MAX_BACKUP: u64 = 512 * 1024 * 1024;

impl Vault {
    pub fn export_backup(&self, destination: &Path) -> Result<(), VaultError> {
        self.ensure_unlocked()?;
        if destination.exists() {
            return Err(VaultError::AlreadyInitialized);
        }
        let salt: String =
            self.conn
                .query_row("SELECT value FROM meta WHERE key='master_salt'", [], |r| {
                    r.get(0)
                })?;
        let iterations: String = self.conn.query_row(
            "SELECT value FROM meta WHERE key='kdf_iterations'",
            [],
            |r| r.get(0),
        )?;
        let iterations = iterations
            .parse::<u32>()
            .map_err(|_| VaultError::InvalidSchema("kdf_iterations".into()))?;
        let stage = self
            .home()
            .join(format!("backup-{}.db", uuid::Uuid::new_v4()));
        let result = (|| {
            self.backup_to(&stage)?;
            let bytes = Zeroizing::new(std::fs::read(&stage)?);
            let key = self.export_resume_key()?;
            let archive = Archive {
                format: "pman-encrypted-backup".into(),
                version: 1,
                salt,
                kdf_iterations: iterations,
                ciphertext: STANDARD.encode(crate::vault::encrypt(&key, &bytes)?),
            };
            let content = serde_json::to_vec(&archive)?;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)?;
            file.write_all(&content)?;
            file.sync_all()?;
            Ok(())
        })();
        let _ = std::fs::remove_file(stage);
        result
    }

    pub fn import_backup(
        source: &Path,
        destination_home: &Path,
        password: &str,
    ) -> Result<Self, VaultError> {
        if destination_home.join("vault.db").exists() {
            return Err(VaultError::AlreadyInitialized);
        }
        let file = std::fs::File::open(source)?;
        if file.metadata()?.len() > MAX_BACKUP {
            return Err(VaultError::InvalidSchema("backup too large".into()));
        }
        let mut content = Vec::new();
        file.take(MAX_BACKUP + 1).read_to_end(&mut content)?;
        let archive: Archive = serde_json::from_slice(&content)?;
        if archive.format != "pman-encrypted-backup"
            || archive.version != 1
            || archive.kdf_iterations == 0
            || archive.kdf_iterations > 10_000_000
        {
            return Err(VaultError::InvalidSchema("unsupported backup".into()));
        }
        let salt = hex::decode(archive.salt).map_err(|_| VaultError::Crypto)?;
        if salt.len() != crate::vault::SALT_BYTES {
            return Err(VaultError::Crypto);
        }
        let key = Zeroizing::new(crate::vault::derive_kek(
            password,
            &salt,
            archive.kdf_iterations,
        )?);
        let cipher = STANDARD
            .decode(archive.ciphertext)
            .map_err(|_| VaultError::Crypto)?;
        let plain = Zeroizing::new(
            crate::vault::decrypt(&key, &cipher).map_err(|_| VaultError::InvalidPassword)?,
        );
        std::fs::create_dir_all(destination_home)?;
        let stage = destination_home.join(format!("restore-{}.db", uuid::Uuid::new_v4()));
        let result = (|| {
            std::fs::write(&stage, &plain)?;
            Vault::import_snapshot(&stage, destination_home, password, true)
        })();
        let _ = std::fs::remove_file(stage);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn encrypted_backup_authenticates_and_restores_without_client_identities() {
        let root = tempfile::tempdir().unwrap();
        let mut v = Vault::open(root.path().join("source")).unwrap();
        v.create("synthetic-password").unwrap();
        v.add_site(crate::SiteInput::new(
            "private title",
            "",
            "password",
            json!({"password":"synthetic-secret"}),
        ))
        .unwrap();
        let path = root.path().join("backup.pman");
        v.export_backup(&path).unwrap();
        let file = std::fs::read_to_string(&path).unwrap();
        assert!(!file.contains("private title"));
        assert!(!file.contains("synthetic-secret"));
        assert!(Vault::import_backup(&path, &root.path().join("bad"), "incorrect").is_err());
        let restored =
            Vault::import_backup(&path, &root.path().join("restored"), "synthetic-password")
                .unwrap();
        assert_eq!(
            restored.get_site_secret("private title").unwrap()["password"],
            "synthetic-secret"
        );
        assert!(restored.list_clients().unwrap().is_empty());
    }
}
