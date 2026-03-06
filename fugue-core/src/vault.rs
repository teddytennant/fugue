#![deny(unsafe_code)]

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::config::VaultBackend;
use crate::error::{FugueError, Result};

const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 32;
const SALT_SIZE: usize = 32;
const PBKDF2_ITERATIONS: u32 = 600_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedVaultData {
    /// Base64-encoded encrypted payload
    data: String,
    /// Base64-encoded nonce
    nonce: String,
    /// Base64-encoded salt for key derivation
    salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct VaultStore {
    credentials: HashMap<String, String>,
}

pub struct Vault {
    backend: VaultBackend,
    file_path: PathBuf,
    master_key: Option<[u8; KEY_SIZE]>,
}

impl Vault {
    pub fn new(backend: VaultBackend, file_path: Option<PathBuf>) -> Self {
        let file_path = file_path.unwrap_or_else(|| {
            dirs::data_dir()
                .unwrap_or_else(|| PathBuf::from(".local/share"))
                .join("fugue")
                .join("vault.enc")
        });

        Self {
            backend,
            file_path,
            master_key: None,
        }
    }

    /// Initialize vault with a master key (derived from password or generated)
    pub fn init_with_key(&mut self, key: [u8; KEY_SIZE]) {
        self.master_key = Some(key);
    }

    /// Generate a new random master key
    pub fn generate_key() -> [u8; KEY_SIZE] {
        let mut key = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Generate a random salt for password-based key derivation
    pub fn generate_salt() -> [u8; SALT_SIZE] {
        let mut salt = [0u8; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);
        salt
    }

    /// Derive a master key from a password and salt using PBKDF2-HMAC-SHA256
    pub fn derive_key_from_password(password: &str, salt: &[u8; SALT_SIZE]) -> Result<[u8; KEY_SIZE]> {
        let mut key = [0u8; KEY_SIZE];
        pbkdf2::<Hmac<Sha256>>(
            password.as_bytes(),
            salt,
            PBKDF2_ITERATIONS,
            &mut key,
        )
        .map_err(|e| FugueError::Vault(format!("PBKDF2 key derivation failed: {}", e)))?;
        Ok(key)
    }

    /// Set a credential in the vault
    pub fn set(&self, name: &str, value: &str) -> Result<()> {
        if name.is_empty() {
            return Err(FugueError::Vault(
                "credential name cannot be empty".to_string(),
            ));
        }
        match self.backend {
            VaultBackend::EncryptedFile => self.set_encrypted_file(name, value),
            VaultBackend::Keyring => self.set_keyring(name, value),
        }
    }

    /// Get a credential from the vault
    pub fn get(&self, name: &str) -> Result<Option<String>> {
        match self.backend {
            VaultBackend::EncryptedFile => self.get_encrypted_file(name),
            VaultBackend::Keyring => self.get_keyring(name),
        }
    }

    /// Remove a credential from the vault
    pub fn remove(&self, name: &str) -> Result<()> {
        match self.backend {
            VaultBackend::EncryptedFile => self.remove_encrypted_file(name),
            VaultBackend::Keyring => self.remove_keyring(name),
        }
    }

    /// List all credential names
    pub fn list(&self) -> Result<Vec<String>> {
        match self.backend {
            VaultBackend::EncryptedFile => self.list_encrypted_file(),
            VaultBackend::Keyring => Err(FugueError::Vault(
                "keyring backend does not support listing all credentials".to_string(),
            )),
        }
    }

    /// Resolve a credential reference (e.g., "vault:my-key") to its value
    pub fn resolve_credential(&self, reference: &str) -> Result<String> {
        let name = reference
            .strip_prefix("vault:")
            .ok_or_else(|| {
                FugueError::Vault(format!(
                    "invalid credential reference '{}'; must start with 'vault:'",
                    reference
                ))
            })?;

        self.get(name)?.ok_or_else(|| {
            FugueError::Vault(format!("credential '{}' not found in vault", name))
        })
    }

    // --- Encrypted file backend ---

    fn get_master_key(&self) -> Result<&[u8; KEY_SIZE]> {
        self.master_key.as_ref().ok_or_else(|| {
            FugueError::Vault("vault not initialized: no master key set".to_string())
        })
    }

    fn load_store(&self) -> Result<VaultStore> {
        if !self.file_path.exists() {
            return Ok(VaultStore::default());
        }

        let content = std::fs::read_to_string(&self.file_path)?;
        let encrypted: EncryptedVaultData = serde_json::from_str(&content)?;

        let key = self.get_master_key()?;
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| FugueError::Vault(format!("invalid key: {}", e)))?;

        let nonce_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &encrypted.nonce,
        )
        .map_err(|e| FugueError::Vault(format!("invalid nonce: {}", e)))?;

        let ciphertext = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &encrypted.data,
        )
        .map_err(|e| FugueError::Vault(format!("invalid ciphertext: {}", e)))?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| FugueError::Vault(format!("decryption failed: {}", e)))?;

        let store: VaultStore = serde_json::from_slice(&plaintext)?;
        Ok(store)
    }

    fn save_store(&self, store: &VaultStore) -> Result<()> {
        let key = self.get_master_key()?;
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| FugueError::Vault(format!("invalid key: {}", e)))?;

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = serde_json::to_vec(store)?;
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| FugueError::Vault(format!("encryption failed: {}", e)))?;

        use base64::Engine;
        let encrypted = EncryptedVaultData {
            data: base64::engine::general_purpose::STANDARD.encode(&ciphertext),
            nonce: base64::engine::general_purpose::STANDARD.encode(nonce_bytes),
            salt: base64::engine::general_purpose::STANDARD.encode([0u8; 16]), // placeholder
        };

        if let Some(parent) = self.file_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(&encrypted)?;
        std::fs::write(&self.file_path, content)?;
        Ok(())
    }

    fn set_encrypted_file(&self, name: &str, value: &str) -> Result<()> {
        let mut store = self.load_store()?;
        store.credentials.insert(name.to_string(), value.to_string());
        self.save_store(&store)
    }

    fn get_encrypted_file(&self, name: &str) -> Result<Option<String>> {
        let store = self.load_store()?;
        Ok(store.credentials.get(name).cloned())
    }

    fn remove_encrypted_file(&self, name: &str) -> Result<()> {
        let mut store = self.load_store()?;
        store.credentials.remove(name);
        self.save_store(&store)
    }

    fn list_encrypted_file(&self) -> Result<Vec<String>> {
        let store = self.load_store()?;
        let mut names: Vec<String> = store.credentials.keys().cloned().collect();
        names.sort();
        Ok(names)
    }

    // --- Keyring backend ---

    fn keyring_not_implemented() -> FugueError {
        FugueError::Vault(
            "Keyring backend is not yet implemented. Use 'file' or 'encrypted-file' instead."
                .to_string(),
        )
    }

    fn set_keyring(&self, _name: &str, _value: &str) -> Result<()> {
        Err(Self::keyring_not_implemented())
    }

    fn get_keyring(&self, _name: &str) -> Result<Option<String>> {
        Err(Self::keyring_not_implemented())
    }

    fn remove_keyring(&self, _name: &str) -> Result<()> {
        Err(Self::keyring_not_implemented())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::TempDir;

    fn test_vault(dir: &Path) -> Vault {
        let mut vault = Vault::new(
            VaultBackend::EncryptedFile,
            Some(dir.join("vault.enc")),
        );
        vault.init_with_key(Vault::generate_key());
        vault
    }

    #[test]
    fn test_set_and_get_credential() {
        let dir = TempDir::new().unwrap();
        let vault = test_vault(dir.path());

        vault.set("api-key", "sk-test-12345").unwrap();
        let value = vault.get("api-key").unwrap();
        assert_eq!(value, Some("sk-test-12345".to_string()));
    }

    #[test]
    fn test_get_nonexistent_credential() {
        let dir = TempDir::new().unwrap();
        let vault = test_vault(dir.path());

        let value = vault.get("nonexistent").unwrap();
        assert_eq!(value, None);
    }

    #[test]
    fn test_remove_credential() {
        let dir = TempDir::new().unwrap();
        let vault = test_vault(dir.path());

        vault.set("api-key", "sk-test-12345").unwrap();
        vault.remove("api-key").unwrap();
        let value = vault.get("api-key").unwrap();
        assert_eq!(value, None);
    }

    #[test]
    fn test_list_credentials() {
        let dir = TempDir::new().unwrap();
        let vault = test_vault(dir.path());

        vault.set("key-b", "value-b").unwrap();
        vault.set("key-a", "value-a").unwrap();
        vault.set("key-c", "value-c").unwrap();

        let names = vault.list().unwrap();
        assert_eq!(names, vec!["key-a", "key-b", "key-c"]);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let dir = TempDir::new().unwrap();
        let key = Vault::generate_key();

        let mut vault = Vault::new(
            VaultBackend::EncryptedFile,
            Some(dir.path().join("vault.enc")),
        );
        vault.init_with_key(key);

        vault.set("secret", "super-secret-value").unwrap();

        // Create a new vault instance with the same key
        let mut vault2 = Vault::new(
            VaultBackend::EncryptedFile,
            Some(dir.path().join("vault.enc")),
        );
        vault2.init_with_key(key);

        let value = vault2.get("secret").unwrap();
        assert_eq!(value, Some("super-secret-value".to_string()));
    }

    #[test]
    fn test_wrong_key_fails_decrypt() {
        let dir = TempDir::new().unwrap();

        let mut vault = Vault::new(
            VaultBackend::EncryptedFile,
            Some(dir.path().join("vault.enc")),
        );
        vault.init_with_key(Vault::generate_key());
        vault.set("secret", "value").unwrap();

        // Try with different key
        let mut vault2 = Vault::new(
            VaultBackend::EncryptedFile,
            Some(dir.path().join("vault.enc")),
        );
        vault2.init_with_key(Vault::generate_key());

        let result = vault2.get("secret");
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_credential_reference() {
        let dir = TempDir::new().unwrap();
        let vault = test_vault(dir.path());

        vault.set("my-api-key", "actual-key-value").unwrap();
        let resolved = vault.resolve_credential("vault:my-api-key").unwrap();
        assert_eq!(resolved, "actual-key-value");
    }

    #[test]
    fn test_resolve_invalid_reference() {
        let dir = TempDir::new().unwrap();
        let vault = test_vault(dir.path());

        let result = vault.resolve_credential("not-a-vault-ref");
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_missing_credential() {
        let dir = TempDir::new().unwrap();
        let vault = test_vault(dir.path());

        let result = vault.resolve_credential("vault:nonexistent");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not found"));
    }

    #[test]
    fn test_overwrite_credential() {
        let dir = TempDir::new().unwrap();
        let vault = test_vault(dir.path());

        vault.set("key", "value1").unwrap();
        vault.set("key", "value2").unwrap();
        let value = vault.get("key").unwrap();
        assert_eq!(value, Some("value2".to_string()));
    }

    #[test]
    fn test_derive_key_from_password() {
        let salt = Vault::generate_salt();
        let key1 = Vault::derive_key_from_password("my-password", &salt).unwrap();
        let key2 = Vault::derive_key_from_password("my-password", &salt).unwrap();
        assert_eq!(key1, key2);

        // Different password produces different key
        let key3 = Vault::derive_key_from_password("different-password", &salt).unwrap();
        assert_ne!(key1, key3);

        // Different salt produces different key
        let salt2 = Vault::generate_salt();
        let key4 = Vault::derive_key_from_password("my-password", &salt2).unwrap();
        assert_ne!(key1, key4);
    }

    #[test]
    fn test_password_derived_key_roundtrip() {
        let dir = TempDir::new().unwrap();
        let salt = Vault::generate_salt();
        let key = Vault::derive_key_from_password("test-password-123", &salt).unwrap();

        let mut vault = Vault::new(
            VaultBackend::EncryptedFile,
            Some(dir.path().join("vault.enc")),
        );
        vault.init_with_key(key);
        vault.set("secret", "password-protected-value").unwrap();

        // Re-derive the key from the same password and salt
        let key2 = Vault::derive_key_from_password("test-password-123", &salt).unwrap();
        let mut vault2 = Vault::new(
            VaultBackend::EncryptedFile,
            Some(dir.path().join("vault.enc")),
        );
        vault2.init_with_key(key2);

        let value = vault2.get("secret").unwrap();
        assert_eq!(value, Some("password-protected-value".to_string()));
    }

    #[test]
    fn test_wrong_password_fails() {
        let dir = TempDir::new().unwrap();
        let salt = Vault::generate_salt();
        let key = Vault::derive_key_from_password("correct-password", &salt).unwrap();

        let mut vault = Vault::new(
            VaultBackend::EncryptedFile,
            Some(dir.path().join("vault.enc")),
        );
        vault.init_with_key(key);
        vault.set("secret", "value").unwrap();

        // Try with wrong password
        let wrong_key = Vault::derive_key_from_password("wrong-password", &salt).unwrap();
        let mut vault2 = Vault::new(
            VaultBackend::EncryptedFile,
            Some(dir.path().join("vault.enc")),
        );
        vault2.init_with_key(wrong_key);

        let result = vault2.get("secret");
        assert!(result.is_err());
    }

    #[test]
    fn test_keyring_backend_returns_error() {
        let dir = TempDir::new().unwrap();
        let mut vault = Vault::new(
            VaultBackend::Keyring,
            Some(dir.path().join("vault.enc")),
        );
        vault.init_with_key(Vault::generate_key());

        let set_err = vault.set("key", "value").unwrap_err().to_string();
        assert!(set_err.contains("Keyring backend is not yet implemented"));

        let get_err = vault.get("key").unwrap_err().to_string();
        assert!(get_err.contains("Keyring backend is not yet implemented"));

        let remove_err = vault.remove("key").unwrap_err().to_string();
        assert!(remove_err.contains("Keyring backend is not yet implemented"));
    }

    #[test]
    fn test_keyring_list_returns_error() {
        let dir = TempDir::new().unwrap();
        let mut vault = Vault::new(
            VaultBackend::Keyring,
            Some(dir.path().join("vault.enc")),
        );
        vault.init_with_key(Vault::generate_key());

        let list_err = vault.list().unwrap_err().to_string();
        assert!(list_err.contains("does not support listing"));
    }

    #[test]
    fn test_vault_uninitialized_set_fails() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::new(
            VaultBackend::EncryptedFile,
            Some(dir.path().join("vault.enc")),
        );
        // No init_with_key called — set requires the key for encryption

        let set_err = vault.set("key", "value").unwrap_err().to_string();
        assert!(set_err.contains("no master key"));
    }

    #[test]
    fn test_vault_uninitialized_get_on_existing_file_fails() {
        let dir = TempDir::new().unwrap();
        let vault_path = dir.path().join("vault.enc");

        // First, create a valid vault file
        {
            let mut v = Vault::new(VaultBackend::EncryptedFile, Some(vault_path.clone()));
            v.init_with_key(Vault::generate_key());
            v.set("key", "value").unwrap();
        }

        // Now try to read without initializing the key
        let vault = Vault::new(VaultBackend::EncryptedFile, Some(vault_path));
        let get_err = vault.get("key").unwrap_err().to_string();
        assert!(get_err.contains("no master key"));
    }

    #[test]
    fn test_vault_empty_credential_name_rejected() {
        let dir = TempDir::new().unwrap();
        let vault = test_vault(dir.path());

        let result = vault.set("", "value");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_vault_special_characters_in_value() {
        let dir = TempDir::new().unwrap();
        let vault = test_vault(dir.path());

        let special = "key with spaces & special chars: !@#$%^&*(){}[]|\\:\";<>?,./~`";
        vault.set("special", special).unwrap();
        let value = vault.get("special").unwrap();
        assert_eq!(value, Some(special.to_string()));
    }

    #[test]
    fn test_vault_unicode_values() {
        let dir = TempDir::new().unwrap();
        let vault = test_vault(dir.path());

        let unicode = "key-\u{1F600}-emoji-\u{4E16}\u{754C}";
        vault.set("unicode", unicode).unwrap();
        let value = vault.get("unicode").unwrap();
        assert_eq!(value, Some(unicode.to_string()));
    }

    #[test]
    fn test_vault_large_value() {
        let dir = TempDir::new().unwrap();
        let vault = test_vault(dir.path());

        let large = "x".repeat(100_000);
        vault.set("large", &large).unwrap();
        let value = vault.get("large").unwrap();
        assert_eq!(value, Some(large));
    }

    #[test]
    fn test_vault_multiple_credentials_persistence() {
        let dir = TempDir::new().unwrap();
        let key = Vault::generate_key();

        {
            let mut vault = Vault::new(
                VaultBackend::EncryptedFile,
                Some(dir.path().join("vault.enc")),
            );
            vault.init_with_key(key);
            vault.set("key1", "value1").unwrap();
            vault.set("key2", "value2").unwrap();
            vault.set("key3", "value3").unwrap();
        }

        {
            let mut vault = Vault::new(
                VaultBackend::EncryptedFile,
                Some(dir.path().join("vault.enc")),
            );
            vault.init_with_key(key);
            assert_eq!(vault.get("key1").unwrap(), Some("value1".to_string()));
            assert_eq!(vault.get("key2").unwrap(), Some("value2".to_string()));
            assert_eq!(vault.get("key3").unwrap(), Some("value3".to_string()));
            assert_eq!(vault.list().unwrap(), vec!["key1", "key2", "key3"]);
        }
    }

    #[test]
    fn test_vault_remove_nonexistent() {
        let dir = TempDir::new().unwrap();
        let vault = test_vault(dir.path());

        // Removing a nonexistent key should succeed (no-op)
        vault.remove("nonexistent").unwrap();
    }

    #[test]
    fn test_vault_resolve_empty_prefix() {
        let dir = TempDir::new().unwrap();
        let vault = test_vault(dir.path());

        let result = vault.resolve_credential("vault:");
        // "vault:" with empty name should look up "" key
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_vault_corrupted_file() {
        let dir = TempDir::new().unwrap();
        let vault_path = dir.path().join("vault.enc");

        // Write garbage to vault file
        std::fs::write(&vault_path, "this is not valid json").unwrap();

        let mut vault = Vault::new(
            VaultBackend::EncryptedFile,
            Some(vault_path),
        );
        vault.init_with_key(Vault::generate_key());

        let result = vault.get("key");
        assert!(result.is_err());
    }

    #[test]
    fn test_vault_different_salts_produce_different_keys() {
        let salt1 = Vault::generate_salt();
        let salt2 = Vault::generate_salt();
        // Salts are random so they should differ
        assert_ne!(salt1, salt2);

        let key1 = Vault::derive_key_from_password("same-password", &salt1).unwrap();
        let key2 = Vault::derive_key_from_password("same-password", &salt2).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_vault_generate_key_is_random() {
        let key1 = Vault::generate_key();
        let key2 = Vault::generate_key();
        assert_ne!(key1, key2);
    }
}
