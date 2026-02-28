#![deny(unsafe_code)]

use rusqlite::{params, Connection};
use std::path::Path;

use crate::error::Result;

pub struct StateStore {
    conn: Connection,
}

impl StateStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;
        let store = Self { conn };
        store.init_tables()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.init_tables()?;
        Ok(store)
    }

    fn init_tables(&self) -> Result<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS kv_store (
                namespace TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (namespace, key)
            );

            CREATE TABLE IF NOT EXISTS conversation_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                sender_name TEXT,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                message_id TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_conversation_channel
                ON conversation_history(channel, created_at);

            CREATE INDEX IF NOT EXISTS idx_kv_namespace
                ON kv_store(namespace);
            ",
        )?;
        Ok(())
    }

    // --- Key-Value Store ---

    pub fn kv_set(&self, namespace: &str, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO kv_store (namespace, key, value, updated_at)
             VALUES (?1, ?2, ?3, datetime('now'))",
            params![namespace, key, value],
        )?;
        Ok(())
    }

    pub fn kv_get(&self, namespace: &str, key: &str) -> Result<Option<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM kv_store WHERE namespace = ?1 AND key = ?2")?;

        let result = stmt
            .query_row(params![namespace, key], |row| row.get(0))
            .optional()?;

        Ok(result)
    }

    pub fn kv_delete(&self, namespace: &str, key: &str) -> Result<bool> {
        let count = self.conn.execute(
            "DELETE FROM kv_store WHERE namespace = ?1 AND key = ?2",
            params![namespace, key],
        )?;
        Ok(count > 0)
    }

    pub fn kv_list_keys(&self, namespace: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT key FROM kv_store WHERE namespace = ?1 ORDER BY key")?;

        let keys = stmt
            .query_map(params![namespace], |row| row.get(0))?
            .collect::<std::result::Result<Vec<String>, _>>()?;

        Ok(keys)
    }

    // --- Conversation History ---

    pub fn add_message(
        &self,
        channel: &str,
        sender_id: &str,
        sender_name: Option<&str>,
        role: &str,
        content: &str,
        message_id: Option<&str>,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO conversation_history (channel, sender_id, sender_name, role, content, message_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![channel, sender_id, sender_name, role, content, message_id],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn get_recent_messages(
        &self,
        channel: &str,
        limit: usize,
    ) -> Result<Vec<ConversationMessage>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, channel, sender_id, sender_name, role, content, message_id, created_at
             FROM conversation_history
             WHERE channel = ?1
             ORDER BY created_at DESC
             LIMIT ?2",
        )?;

        let messages = stmt
            .query_map(params![channel, limit as i64], |row| {
                Ok(ConversationMessage {
                    id: row.get(0)?,
                    channel: row.get(1)?,
                    sender_id: row.get(2)?,
                    sender_name: row.get(3)?,
                    role: row.get(4)?,
                    content: row.get(5)?,
                    message_id: row.get(6)?,
                    created_at: row.get(7)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        // Reverse to get chronological order
        let mut messages = messages;
        messages.reverse();
        Ok(messages)
    }

    pub fn clear_channel_history(&self, channel: &str) -> Result<usize> {
        let count = self.conn.execute(
            "DELETE FROM conversation_history WHERE channel = ?1",
            params![channel],
        )?;
        Ok(count)
    }
}

use rusqlite::OptionalExtension;

#[derive(Debug, Clone)]
pub struct ConversationMessage {
    pub id: i64,
    pub channel: String,
    pub sender_id: String,
    pub sender_name: Option<String>,
    pub role: String,
    pub content: String,
    pub message_id: Option<String>,
    pub created_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kv_set_and_get() {
        let store = StateStore::open_in_memory().unwrap();
        store.kv_set("plugin:echo", "counter", "42").unwrap();
        let value = store.kv_get("plugin:echo", "counter").unwrap();
        assert_eq!(value, Some("42".to_string()));
    }

    #[test]
    fn test_kv_get_nonexistent() {
        let store = StateStore::open_in_memory().unwrap();
        let value = store.kv_get("ns", "missing").unwrap();
        assert_eq!(value, None);
    }

    #[test]
    fn test_kv_overwrite() {
        let store = StateStore::open_in_memory().unwrap();
        store.kv_set("ns", "key", "v1").unwrap();
        store.kv_set("ns", "key", "v2").unwrap();
        let value = store.kv_get("ns", "key").unwrap();
        assert_eq!(value, Some("v2".to_string()));
    }

    #[test]
    fn test_kv_delete() {
        let store = StateStore::open_in_memory().unwrap();
        store.kv_set("ns", "key", "value").unwrap();
        let deleted = store.kv_delete("ns", "key").unwrap();
        assert!(deleted);
        let value = store.kv_get("ns", "key").unwrap();
        assert_eq!(value, None);
    }

    #[test]
    fn test_kv_delete_nonexistent() {
        let store = StateStore::open_in_memory().unwrap();
        let deleted = store.kv_delete("ns", "missing").unwrap();
        assert!(!deleted);
    }

    #[test]
    fn test_kv_list_keys() {
        let store = StateStore::open_in_memory().unwrap();
        store.kv_set("ns", "b", "1").unwrap();
        store.kv_set("ns", "a", "2").unwrap();
        store.kv_set("ns", "c", "3").unwrap();
        store.kv_set("other", "x", "4").unwrap();

        let keys = store.kv_list_keys("ns").unwrap();
        assert_eq!(keys, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_namespace_isolation() {
        let store = StateStore::open_in_memory().unwrap();
        store.kv_set("ns1", "key", "value1").unwrap();
        store.kv_set("ns2", "key", "value2").unwrap();

        assert_eq!(store.kv_get("ns1", "key").unwrap(), Some("value1".to_string()));
        assert_eq!(store.kv_get("ns2", "key").unwrap(), Some("value2".to_string()));
    }

    #[test]
    fn test_add_and_get_messages() {
        let store = StateStore::open_in_memory().unwrap();

        store.add_message("cli", "user1", Some("Alice"), "user", "Hello!", None).unwrap();
        store.add_message("cli", "assistant", None, "assistant", "Hi there!", None).unwrap();
        store.add_message("cli", "user1", Some("Alice"), "user", "How are you?", None).unwrap();

        let messages = store.get_recent_messages("cli", 10).unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0].content, "Hello!");
        assert_eq!(messages[1].content, "Hi there!");
        assert_eq!(messages[2].content, "How are you?");
    }

    #[test]
    fn test_get_recent_messages_limit() {
        let store = StateStore::open_in_memory().unwrap();

        for i in 0..10 {
            store.add_message("cli", "user1", None, "user", &format!("msg {}", i), None).unwrap();
        }

        let messages = store.get_recent_messages("cli", 3).unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0].content, "msg 7");
        assert_eq!(messages[1].content, "msg 8");
        assert_eq!(messages[2].content, "msg 9");
    }

    #[test]
    fn test_channel_isolation() {
        let store = StateStore::open_in_memory().unwrap();

        store.add_message("cli", "user", None, "user", "cli msg", None).unwrap();
        store.add_message("telegram", "user", None, "user", "tg msg", None).unwrap();

        let cli_msgs = store.get_recent_messages("cli", 10).unwrap();
        assert_eq!(cli_msgs.len(), 1);
        assert_eq!(cli_msgs[0].content, "cli msg");

        let tg_msgs = store.get_recent_messages("telegram", 10).unwrap();
        assert_eq!(tg_msgs.len(), 1);
        assert_eq!(tg_msgs[0].content, "tg msg");
    }

    #[test]
    fn test_clear_channel_history() {
        let store = StateStore::open_in_memory().unwrap();

        store.add_message("cli", "user", None, "user", "msg1", None).unwrap();
        store.add_message("cli", "user", None, "user", "msg2", None).unwrap();

        let count = store.clear_channel_history("cli").unwrap();
        assert_eq!(count, 2);

        let messages = store.get_recent_messages("cli", 10).unwrap();
        assert!(messages.is_empty());
    }

    #[test]
    fn test_file_backed_store() {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("state.db");

        {
            let store = StateStore::open(&db_path).unwrap();
            store.kv_set("ns", "key", "persisted").unwrap();
        }

        {
            let store = StateStore::open(&db_path).unwrap();
            let value = store.kv_get("ns", "key").unwrap();
            assert_eq!(value, Some("persisted".to_string()));
        }
    }

    #[test]
    fn test_kv_empty_namespace_and_key() {
        let store = StateStore::open_in_memory().unwrap();
        store.kv_set("", "", "value").unwrap();
        let value = store.kv_get("", "").unwrap();
        assert_eq!(value, Some("value".to_string()));
    }

    #[test]
    fn test_kv_unicode_keys_and_values() {
        let store = StateStore::open_in_memory().unwrap();
        store.kv_set("\u{1F600}", "\u{4E16}\u{754C}", "\u{1F310}").unwrap();
        let value = store.kv_get("\u{1F600}", "\u{4E16}\u{754C}").unwrap();
        assert_eq!(value, Some("\u{1F310}".to_string()));
    }

    #[test]
    fn test_kv_large_value() {
        let store = StateStore::open_in_memory().unwrap();
        let large = "x".repeat(1_000_000);
        store.kv_set("ns", "large", &large).unwrap();
        let value = store.kv_get("ns", "large").unwrap();
        assert_eq!(value, Some(large));
    }

    #[test]
    fn test_kv_list_keys_empty_namespace() {
        let store = StateStore::open_in_memory().unwrap();
        let keys = store.kv_list_keys("empty-ns").unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn test_messages_with_message_id() {
        let store = StateStore::open_in_memory().unwrap();
        let id = store
            .add_message("cli", "user1", Some("Alice"), "user", "Hello!", Some("msg-123"))
            .unwrap();
        assert!(id > 0);

        let messages = store.get_recent_messages("cli", 10).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_id, Some("msg-123".to_string()));
    }

    #[test]
    fn test_messages_without_sender_name() {
        let store = StateStore::open_in_memory().unwrap();
        store
            .add_message("cli", "user1", None, "user", "Hello!", None)
            .unwrap();

        let messages = store.get_recent_messages("cli", 10).unwrap();
        assert_eq!(messages[0].sender_name, None);
    }

    #[test]
    fn test_messages_chronological_order() {
        let store = StateStore::open_in_memory().unwrap();

        for i in 0..5 {
            store
                .add_message("cli", "user", None, "user", &format!("msg-{}", i), None)
                .unwrap();
        }

        let messages = store.get_recent_messages("cli", 10).unwrap();
        assert_eq!(messages.len(), 5);
        // Should be in chronological order
        for (i, msg) in messages.iter().enumerate() {
            assert_eq!(msg.content, format!("msg-{}", i));
        }
    }

    #[test]
    fn test_get_recent_messages_empty_channel() {
        let store = StateStore::open_in_memory().unwrap();
        let messages = store.get_recent_messages("empty", 10).unwrap();
        assert!(messages.is_empty());
    }

    #[test]
    fn test_get_recent_messages_limit_zero() {
        let store = StateStore::open_in_memory().unwrap();
        store
            .add_message("cli", "user", None, "user", "msg", None)
            .unwrap();

        let messages = store.get_recent_messages("cli", 0).unwrap();
        assert!(messages.is_empty());
    }

    #[test]
    fn test_clear_empty_channel() {
        let store = StateStore::open_in_memory().unwrap();
        let count = store.clear_channel_history("empty").unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_clear_does_not_affect_other_channels() {
        let store = StateStore::open_in_memory().unwrap();
        store.add_message("cli", "user", None, "user", "cli msg", None).unwrap();
        store.add_message("telegram", "user", None, "user", "tg msg", None).unwrap();

        store.clear_channel_history("cli").unwrap();

        let cli_msgs = store.get_recent_messages("cli", 10).unwrap();
        assert!(cli_msgs.is_empty());

        let tg_msgs = store.get_recent_messages("telegram", 10).unwrap();
        assert_eq!(tg_msgs.len(), 1);
    }

    #[test]
    fn test_add_message_returns_incrementing_ids() {
        let store = StateStore::open_in_memory().unwrap();
        let id1 = store.add_message("cli", "user", None, "user", "msg1", None).unwrap();
        let id2 = store.add_message("cli", "user", None, "user", "msg2", None).unwrap();
        let id3 = store.add_message("cli", "user", None, "user", "msg3", None).unwrap();

        assert!(id2 > id1);
        assert!(id3 > id2);
    }

    #[test]
    fn test_open_creates_parent_directories() {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("sub").join("dir").join("state.db");

        let store = StateStore::open(&db_path).unwrap();
        store.kv_set("ns", "key", "value").unwrap();
        assert!(db_path.exists());
    }

    #[test]
    fn test_kv_many_namespaces() {
        let store = StateStore::open_in_memory().unwrap();
        for i in 0..100 {
            store.kv_set(&format!("ns-{}", i), "key", &format!("val-{}", i)).unwrap();
        }

        for i in 0..100 {
            let value = store.kv_get(&format!("ns-{}", i), "key").unwrap();
            assert_eq!(value, Some(format!("val-{}", i)));
        }
    }
}
