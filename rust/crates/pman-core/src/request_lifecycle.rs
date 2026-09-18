//! Durable dispatch intent. An unfinished marker never claims a request was sent.
use crate::{Vault, VaultError};
use rusqlite::params;

impl Vault {
    pub(crate) fn init_request_lifecycle(&self) -> Result<(), VaultError> {
        self.conn.execute_batch("CREATE TABLE IF NOT EXISTS request_lifecycle(id TEXT PRIMARY KEY,harness TEXT NOT NULL,site TEXT NOT NULL,method TEXT NOT NULL,path TEXT NOT NULL,state TEXT NOT NULL,created_at TEXT NOT NULL,finished_at TEXT); CREATE INDEX IF NOT EXISTS idx_request_lifecycle_unfinished ON request_lifecycle(state);")?;
        Ok(())
    }

    /// Called before credentials can reach transport. Only sanitized routing metadata is persisted.
    pub(crate) fn begin_request_lifecycle(
        &mut self,
        harness: &str,
        site: &str,
        method: &str,
        path: &str,
    ) -> Result<String, VaultError> {
        self.ensure_unlocked()?;
        let id = uuid::Uuid::new_v4().simple().to_string();
        self.conn.execute("INSERT INTO request_lifecycle(id,harness,site,method,path,state,created_at) VALUES(?,?,?,?,?,'dispatch_pending',?)",params![id,harness,site,method,path,crate::vault::now()])?;
        Ok(id)
    }

    pub(crate) fn finish_request_lifecycle(
        &mut self,
        id: &str,
        state: &str,
    ) -> Result<(), VaultError> {
        if !matches!(
            state,
            "not_dispatched" | "response_received" | "outcome_unknown"
        ) {
            return Err(VaultError::InvalidSchema(
                "invalid request lifecycle".into(),
            ));
        }
        let tx = self.conn.transaction()?;
        if state == "outcome_unknown" {
            tx.execute("INSERT INTO audit_log(ts,harness,site,method,path,req_id,note) SELECT ?,harness,site,method,path,id,'outcome_unknown: dispatch did not return a complete result; remote outcome unknown, no automatic retry' FROM request_lifecycle WHERE id=? AND finished_at IS NULL",params![crate::vault::now(),id])?;
        }
        tx.execute(
            "UPDATE request_lifecycle SET state=?,finished_at=? WHERE id=? AND finished_at IS NULL",
            params![state, crate::vault::now(), id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Runs only after opening the target workspace. Import uses an isolated copied database.
    pub(crate) fn recover_interrupted_requests(&mut self) -> Result<(), VaultError> {
        let tx = self.conn.transaction()?;
        tx.execute("INSERT INTO audit_log(ts,harness,site,method,path,req_id,note) SELECT ?,harness,site,method,path,id,'outcome_unknown: request interrupted while dispatch was pending; it may or may not have reached the remote service; remote outcome unknown, no automatic retry' FROM request_lifecycle WHERE finished_at IS NULL",[crate::vault::now()])?;
        tx.execute("UPDATE request_lifecycle SET state='outcome_unknown',finished_at=? WHERE finished_at IS NULL",[crate::vault::now()])?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn restart_records_uncertain_dispatch_once_without_request_payload() {
        let temp = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(temp.path()).unwrap();
        vault.create("synthetic-password").unwrap();
        vault
            .add_site(crate::SiteInput::new(
                "api",
                "https://example.test",
                "api_token",
                json!({"token":"synthetic-secret"}),
            ))
            .unwrap();
        let prepared = crate::Broker::new()
            .prepare(
                &mut vault,
                crate::HttpRequest {
                    site: "api".into(),
                    method: "GET".into(),
                    path: "/change".into(),
                    capability: None,
                    query: Some(json!({"value":"private-body"})),
                    json_body: None,
                    form: None,
                },
                None,
            )
            .unwrap();
        let marker: String = vault
            .conn
            .query_row(
                "SELECT harness||site||method||path||state FROM request_lifecycle",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!marker.contains("private-body"));
        assert!(!marker.contains("synthetic-secret"));
        assert!(marker.contains("dispatch_pending"));
        drop(prepared);
        drop(vault);
        let vault = Vault::open(temp.path()).unwrap();
        let audit = vault.query_audit(None, 100).unwrap();
        assert_eq!(
            audit
                .iter()
                .filter(|e| e
                    .note
                    .as_deref()
                    .is_some_and(|n| n.contains("outcome_unknown")))
                .count(),
            1
        );
        assert!(audit[0].note.as_deref().unwrap().contains("may or may not"));
        drop(vault);
        let vault = Vault::open(temp.path()).unwrap();
        assert_eq!(vault.query_audit(None, 100).unwrap().len(), 1);
    }

    #[test]
    fn truncated_remote_response_is_uncertain_and_never_left_unfinished() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 4096];
            let _ = stream.read(&mut buffer).unwrap();
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{").unwrap();
        });
        let temp = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(temp.path()).unwrap();
        vault.create("synthetic-password").unwrap();
        vault
            .add_site(crate::SiteInput::new(
                "api",
                format!("http://{address}"),
                "api_token",
                json!({"token":"synthetic-secret"}),
            ))
            .unwrap();
        let result = crate::Broker::new().call(
            &mut vault,
            crate::HttpRequest {
                site: "api".into(),
                method: "GET".into(),
                path: "/change".into(),
                capability: None,
                query: None,
                json_body: None,
                form: None,
            },
            None,
        );
        server.join().unwrap();
        assert_eq!(result.outcome_unknown, Some(true));
        assert!(result
            .error
            .as_deref()
            .unwrap()
            .contains("no automatic retry"));
        let unfinished: i64 = vault
            .conn
            .query_row(
                "SELECT COUNT(*) FROM request_lifecycle WHERE finished_at IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(unfinished, 0);
        let audit = vault.query_audit(None, 100).unwrap();
        assert!(audit.iter().any(|e| e
            .note
            .as_deref()
            .is_some_and(|n| n.contains("outcome_unknown"))));
    }
}
